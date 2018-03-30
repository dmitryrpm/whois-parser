package whois_parser

import (
	"io/ioutil"
	"reflect"
	"strings"
	"testing"

	"github.com/dmitryrpm/whois-parser/parser"
)

var fixtures = []struct {
	in  string
	out *parser.WhoisInfo
}{
	// IANA
	{"whois.iana.org/____asd", &parser.WhoisInfo{
		Error:       parser.ValidateError,
		NameServers: []string{},
	}},
	{"whois.iana.org/a-haimer", &parser.WhoisInfo{
		Error:       parser.NotFoundError,
		NameServers: []string{},
	}},
	{"whois.iana.org/google.com", &parser.WhoisInfo{
		DomainName: "com",
		NameServers: []string{
			"A.GTLD-SERVERS.NET 192.5.6.30 2001:503:a83e:0:0:0:2:30",
			"B.GTLD-SERVERS.NET 192.33.14.30 2001:503:231d:0:0:0:2:30",
			"C.GTLD-SERVERS.NET 192.26.92.30 2001:503:83eb:0:0:0:0:30",
			"D.GTLD-SERVERS.NET 192.31.80.30 2001:500:856e:0:0:0:0:30",
			"E.GTLD-SERVERS.NET 192.12.94.30 2001:502:1ca1:0:0:0:0:30",
			"F.GTLD-SERVERS.NET 192.35.51.30 2001:503:d414:0:0:0:0:30",
			"G.GTLD-SERVERS.NET 192.42.93.30 2001:503:eea3:0:0:0:0:30",
			"H.GTLD-SERVERS.NET 192.54.112.30 2001:502:8cc:0:0:0:0:30",
			"I.GTLD-SERVERS.NET 192.43.172.30 2001:503:39c1:0:0:0:0:30",
			"J.GTLD-SERVERS.NET 192.48.79.30 2001:502:7094:0:0:0:0:30",
			"K.GTLD-SERVERS.NET 192.52.178.30 2001:503:d2d:0:0:0:0:30",
			"L.GTLD-SERVERS.NET 192.41.162.30 2001:500:d937:0:0:0:0:30",
			"M.GTLD-SERVERS.NET 192.55.83.30 2001:501:b1f9:0:0:0:0:30"},
		Refer: "whois.verisign-grs.com",
	}},
	// whois.tcinet.ru
	{"whois.tcinet.ru/suwer.ru", &parser.WhoisInfo{
		DomainName:  "suwer.ru",
		NameServers: []string{"ns1.reg.ru.", "ns2.reg.ru."},
	}},
	// verisign-grs.com
	{"whois.verisign-grs.com/____asd", &parser.WhoisInfo{
		NameServers: []string{},
		Error:       parser.NotFoundError,
		Status:      []string{},
	}},
	{"whois.verisign-grs.com/google.com", &parser.WhoisInfo{
		DomainName:     "google.com",
		NameServers:    []string{"NS1.GOOGLE.COM", "NS2.GOOGLE.COM", "NS3.GOOGLE.COM", "NS4.GOOGLE.COM"},
		CreationDate:   `1997-09-15T04:00:00Z`,
		UpdatedDate:    `2018-02-21T18:36:40Z`,
		ExpirationDate: `2020-09-14T04:00:00Z`,
		Registrar: parser.WhoisRegistrar{
			WhoisServer:  "whois.markmonitor.com",
			Organization: "MarkMonitor Inc.",
			Phone:        "+1.2083895740",
			Email:        "abusecomplaints@markmonitor.com",
			IanaID:       292,
			URL:          "http://www.markmonitor.com",
		},
		Status: []string{
			"clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited",
			"clientTransferProhibited https://icann.org/epp#clientTransferProhibited",
			"clientUpdateProhibited https://icann.org/epp#clientUpdateProhibited",
			"serverDeleteProhibited https://icann.org/epp#serverDeleteProhibited",
			"serverTransferProhibited https://icann.org/epp#serverTransferProhibited",
			"serverUpdateProhibited https://icann.org/epp#serverUpdateProhibited"},
	}},
	// whois.markmonitor.com
	{"whois.markmonitor.com/google.com", &parser.WhoisInfo{
		DomainName:     "google.com",
		NameServers:    []string{"ns4.google.com", "ns3.google.com", "ns1.google.com", "ns2.google.com"},
		CreationDate:   `1997-09-15T00:00:00-0700`,
		UpdatedDate:    `2018-02-21T10:45:07-0800`,
		ExpirationDate: `2020-09-13T21:00:00-0700`,
		Registrar: parser.WhoisRegistrar{
			WhoisServer:  "whois.markmonitor.com",
			Organization: "MarkMonitor, Inc.",
			Phone:        "+1.2083895740",
			Email:        "abusecomplaints@markmonitor.com",
			IanaID:       292,
			URL:          "http://www.markmonitor.com",
		},
		Registrant: parser.WhoisRegistrant{
			Name:         "Domain Administrator",
			Organization: "Google LLC",
			Address:      "1600 Amphitheatre Parkway,",
			City:         "Mountain View",
			State:        "CA",
			ZipCode:      "94043",
			Country:      "US",
			Phone:        "+1.6502530001",
			Fax:          "+1.6502530000",
			Email:        "dns-admin@google.com"},
		Status: []string{
			"clientUpdateProhibited (https://www.icann.org/epp#clientUpdateProhibited)",
			"clientTransferProhibited (https://www.icann.org/epp#clientTransferProhibited)",
			"clientDeleteProhibited (https://www.icann.org/epp#clientDeleteProhibited)",
			"serverUpdateProhibited (https://www.icann.org/epp#serverUpdateProhibited)",
			"serverTransferProhibited (https://www.icann.org/epp#serverTransferProhibited)",
			"serverDeleteProhibited (https://www.icann.org/epp#serverDeleteProhibited)"},
	}},
}

func TestFixtures(t *testing.T) {
	for _, fixture := range fixtures {
		text, _ := ioutil.ReadFile("./data/" + fixture.in)
		name := strings.Split(fixture.in, "/")[0]
		p := parser.New(name)
		info := p.Parse(text)
		if !reflect.DeepEqual(info, fixture.out) {
			t.Errorf("\nname: %s \ngot: %#v, \nexc: %#v", name, info, fixture.out)
		}
	}
}
