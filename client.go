package linode

import (
	"context"
	"fmt"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/libdns/libdns"
	"github.com/linode/linodego"
)

func (p *Provider) init(ctx context.Context) {
	p.once.Do(func() {
		p.client = linodego.NewClient(http.DefaultClient)
		if p.APIToken != "" {
			p.client.SetToken(p.APIToken)
		}
		if p.APIURL != "" {
			p.client.SetBaseURL(p.APIURL)
		}
		if p.APIVersion != "" {
			p.client.SetAPIVersion(p.APIVersion)
		}
	})
}

func (p *Provider) getDomainIDByZone(ctx context.Context, zone string) (int, error) {
	f := linodego.Filter{}
	f.AddField(linodego.Eq, "domain", libdns.AbsoluteName(zone, ""))
	filter, err := f.MarshalJSON()
	if err != nil {
		return 0, err
	}
	listOptions := linodego.NewListOptions(0, string(filter))
	domains, err := p.client.ListDomains(ctx, listOptions)
	if err != nil {
		return 0, fmt.Errorf("could not list domains: %v", err)
	}
	if len(domains) == 0 {
		return 0, fmt.Errorf("could not find the domain provided")
	}
	return domains[0].ID, nil
}

func (p *Provider) listDomainRecords(ctx context.Context, zone string, domainID int) ([]libdns.Record, error) {
	listOptions := linodego.NewListOptions(0, "")
	linodeRecords, err := p.client.ListDomainRecords(ctx, domainID, listOptions)
	if err != nil {
		return nil, fmt.Errorf("could not list domain records: %v", err)
	}
	records := make([]libdns.Record, 0, len(linodeRecords))
	for _, linodeRecord := range linodeRecords {
		record := convertToLibdnsRecord(zone, &linodeRecord)
		if record != nil {
			records = append(records, record)
		}
	}
	return records, nil
}

func (p *Provider) createOrUpdateDomainRecord(ctx context.Context, zone string, domainID int, record libdns.Record) (libdns.Record, error) {
	// Check if this record has an ID (indicating it exists)
	if providerData, ok := getProviderData(record); ok {
		if id, exists := providerData["id"]; exists {
			updatedRecord, err := p.updateDomainRecord(ctx, zone, domainID, record, id.(string))
			if err != nil {
				return nil, err
			}
			return updatedRecord, nil
		}
	}
	
	// No ID found, create new record
	addedRecord, err := p.createDomainRecord(ctx, zone, domainID, record)
	if err != nil {
		return nil, err
	}
	return addedRecord, nil
}

func (p *Provider) createDomainRecord(ctx context.Context, zone string, domainID int, record libdns.Record) (libdns.Record, error) {
	rr := record.RR()
	
	addedLinodeRecord, err := p.client.CreateDomainRecord(ctx, domainID, linodego.DomainRecordCreateOptions{
		Type:   linodego.DomainRecordType(rr.Type),
		Name:   libdns.RelativeName(rr.Name, zone),
		Target: rr.Data,
		TTLSec: int(rr.TTL.Seconds()),
	})
	if err != nil {
		return nil, err
	}
	return mergeWithExistingLibdnsRecord(zone, record, addedLinodeRecord), nil
}

func (p *Provider) updateDomainRecord(ctx context.Context, zone string, domainID int, record libdns.Record, recordIDStr string) (libdns.Record, error) {
	rr := record.RR()
	recordID, err := strconv.Atoi(recordIDStr)
	if err != nil {
		return nil, err
	}
	updatedLinodeRecord, err := p.client.UpdateDomainRecord(ctx, domainID, recordID, linodego.DomainRecordUpdateOptions{
		Type:   linodego.DomainRecordType(rr.Type),
		Name:   libdns.RelativeName(rr.Name, zone),
		Target: rr.Data,
		TTLSec: int(rr.TTL.Seconds()),
	})
	if err != nil {
		return nil, err
	}
	return mergeWithExistingLibdnsRecord(zone, record, updatedLinodeRecord), nil
}

func (p *Provider) deleteDomainRecord(ctx context.Context, domainID int, record libdns.Record) error {
	providerData, ok := getProviderData(record)
	if !ok {
		return fmt.Errorf("record does not have provider data with ID")
	}
	
	id, exists := providerData["id"]
	if !exists {
		return fmt.Errorf("record does not have ID in provider data")
	}
	
	recordID, err := strconv.Atoi(id.(string))
	if err != nil {
		return err
	}
	return p.client.DeleteDomainRecord(ctx, domainID, recordID)
}

func convertToLibdnsRecord(zone string, linodeRecord *linodego.DomainRecord) libdns.Record {
	name := libdns.RelativeName(linodeRecord.Name, zone)
	ttl := time.Duration(linodeRecord.TTLSec) * time.Second
	recordType := string(linodeRecord.Type)
	data := linodeRecord.Target
	
	// Store provider-specific data (like the record ID) in ProviderData
	providerData := map[string]interface{}{
		"id": strconv.Itoa(linodeRecord.ID),
	}
	
	// Convert to specific record types based on DNS record type
	switch strings.ToUpper(recordType) {
	case "A", "AAAA":
		if ip, err := netip.ParseAddr(data); err == nil {
			return libdns.Address{
				Name:         name,
				TTL:          ttl,
				IP:           ip,
				ProviderData: providerData,
			}
		}
	case "TXT":
		return libdns.TXT{
			Name:         name,
			TTL:          ttl,
			Text:         data,
			ProviderData: providerData,
		}
	case "CNAME":
		return libdns.CNAME{
			Name:         name,
			TTL:          ttl,
			Target:       data,
			ProviderData: providerData,
		}
	case "MX":
		// Parse priority and target from data (format: "10 mail.example.com")
		parts := strings.SplitN(data, " ", 2)
		if len(parts) == 2 {
			if preference, err := strconv.Atoi(parts[0]); err == nil {
				return libdns.MX{
					Name:         name,
					TTL:          ttl,
					Preference:   uint16(preference),
					Target:       parts[1],
					ProviderData: providerData,
				}
			}
		}
	case "SRV":
		// Parse SRV data (format: "priority weight port target")
		parts := strings.Fields(data)
		if len(parts) == 4 {
			if priority, err1 := strconv.Atoi(parts[0]); err1 == nil {
				if weight, err2 := strconv.Atoi(parts[1]); err2 == nil {
					if port, err3 := strconv.Atoi(parts[2]); err3 == nil {
						// Parse service and transport from the name (format: _service._transport.name)
						service := ""
						transport := ""
						if strings.HasPrefix(name, "_") {
							nameParts := strings.SplitN(name, ".", 3)
							if len(nameParts) >= 2 {
								service = strings.TrimPrefix(nameParts[0], "_")
								transport = strings.TrimPrefix(nameParts[1], "_")
								if len(nameParts) >= 3 {
									name = nameParts[2]
								} else {
									name = ""
								}
							}
						}
						return libdns.SRV{
							Service:      service,
							Transport:    transport,
							Name:         name,
							TTL:          ttl,
							Priority:     uint16(priority),
							Weight:       uint16(weight),
							Port:         uint16(port),
							Target:       parts[3],
							ProviderData: providerData,
						}
					}
				}
			}
		}
	case "NS":
		return libdns.NS{
			Name:         name,
			TTL:          ttl,
			Target:       data,
			ProviderData: providerData,
		}
	case "CAA":
		// Parse CAA data (format: "flags tag value")
		parts := strings.SplitN(data, " ", 3)
		if len(parts) == 3 {
			if flags, err := strconv.Atoi(parts[0]); err == nil {
				return libdns.CAA{
					Name:         name,
					TTL:          ttl,
					Flags:        uint8(flags),
					Tag:          parts[1],
					Value:        parts[2],
					ProviderData: providerData,
				}
			}
		}
	}
	
	// Fallback to generic RR if no specific type matched
	return libdns.RR{
		Name:         name,
		TTL:          ttl,
		Type:         recordType,
		Data:         data,
	}
}

func mergeWithExistingLibdnsRecord(zone string, existingRecord libdns.Record, linodeRecord *linodego.DomainRecord) libdns.Record {
	// Create a new record based on the Linode record data
	newRecord := convertToLibdnsRecord(zone, linodeRecord)
	
	// If the existing record has the same type, try to preserve any non-provider data
	if existingRecord != nil {
		existingRR := existingRecord.RR()
		newRR := newRecord.RR()
		if existingRR.Type == newRR.Type {
			// For the same record type, the new record should have the updated data
			// The provider data (like ID) will be set from the Linode response
			return newRecord
		}
	}
	
	return newRecord
}

// Helper function to extract provider data from a record
func getProviderData(record libdns.Record) (map[string]interface{}, bool) {
	switch r := record.(type) {
	case libdns.Address:
		if r.ProviderData != nil {
			if data, ok := r.ProviderData.(map[string]interface{}); ok {
				return data, true
			}
		}
	case libdns.TXT:
		if r.ProviderData != nil {
			if data, ok := r.ProviderData.(map[string]interface{}); ok {
				return data, true
			}
		}
	case libdns.CNAME:
		if r.ProviderData != nil {
			if data, ok := r.ProviderData.(map[string]interface{}); ok {
				return data, true
			}
		}
	case libdns.MX:
		if r.ProviderData != nil {
			if data, ok := r.ProviderData.(map[string]interface{}); ok {
				return data, true
			}
		}
	case libdns.SRV:
		if r.ProviderData != nil {
			if data, ok := r.ProviderData.(map[string]interface{}); ok {
				return data, true
			}
		}
	case libdns.NS:
		if r.ProviderData != nil {
			if data, ok := r.ProviderData.(map[string]interface{}); ok {
				return data, true
			}
		}
	case libdns.CAA:
		if r.ProviderData != nil {
			if data, ok := r.ProviderData.(map[string]interface{}); ok {
				return data, true
			}
		}
	}
	return nil, false
}
