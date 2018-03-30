package whois_parser

import (
	"io/ioutil"
	"reflect"
	"testing"
	"strings"
	"github.com/dmitryrpm/whois-parser/parser"
)


var fixtures = []struct {
	in  string
	out *parser.WhoisInfo
}{
	// IANA
	{"whois.iana.org/____asd", &parser.WhoisInfo{
		Error:  "Invalid query ___asd",
		NameServers: []string{},
	}},
	{"whois.iana.org/a-haimer", &parser.WhoisInfo{
		Error:  "This query returned 0 objects",
		NameServers: []string{},
	}},
	{"whois.iana.org/google.com", &parser.WhoisInfo{
		DomainName:  "com",
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
}

func TestFixtures(t *testing.T) {
	for _, fixture := range fixtures {
		text, _ := ioutil.ReadFile("./data/" + fixture.in)
		name := strings.Split(fixture.in, "/")[0]
		p := parser.New(name)
		info := p.Parse(text)
		if !reflect.DeepEqual(info, fixture.out) {
			t.Errorf("\nname: %s \ngot: %#v, \nexc: %#v", name, info, fixture.out)
		}}
}
