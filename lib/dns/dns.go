package dns

import (
	"regexp"

	"github.com/miekg/dns"
)

const DNS_SERVER = "8.8.8.8:53"

var DID_CAS_TMPL = regexp.MustCompile(`^did:cas:v1:([A-Za-z0-9+/]+={0,2})$`)

type TxtRecordClient func(domain string) ([]string, error)

type client struct {
	txtRecordClient TxtRecordClient
}

type Client interface {
	DidCasRecords(domain string) ([]string, error)
}

func NewClient(txtRecordClient TxtRecordClient) Client {
	if txtRecordClient == nil {
		txtRecordClient = DefaultTxtRecordClient
	}
	c := client{txtRecordClient: txtRecordClient}
	return &c
}

func DefaultTxtRecordClient(domain string) ([]string, error) {
	fqdn := dns.Fqdn(domain)
	c := new(dns.Client)
	m := new(dns.Msg)
	m.SetQuestion(fqdn, dns.TypeTXT)

	r, _, err := c.Exchange(m, DNS_SERVER)
	if err != nil {
		return nil, err
	}

	var records []string
	for _, ans := range r.Answer {
		if txt, ok := ans.(*dns.TXT); ok {
			records = append(records, txt.Txt...)
		}
	}
	return records, nil
}

func (c *client) DidCasRecords(domain string) ([]string, error) {
	txtRecords, err := c.txtRecordClient(domain)
	if err != nil {
		return nil, err
	}

	var didCasRecords []string
	for _, record := range txtRecords {
		if DID_CAS_TMPL.MatchString(record) {
			didCasRecords = append(didCasRecords, record)
		}
	}
	return didCasRecords, nil
}
