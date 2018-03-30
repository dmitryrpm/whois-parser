package parser

import (
	"regexp"
	"strings"
)

const (
	DomainName = iota
	NameServers
	Org
	Refer
	Error
)

type Interface interface {
	Parse(data []byte) (wi *WhoisInfo)
}

func New(whois string) Interface {
	v, ok := whoisMap[whois]
	if !ok {
		return NewUglyParser()
	}
	return v()
}


type Parser struct {
	reg    map[int][]*regexp.Regexp
}

var whoisMap = map[string]func() Interface{
	`whois.tcinet.ru`: NewTcinetRuParser,
	`whois.iana.org`: NewIana,
}

func (p *Parser) Parse(data []byte) (wi *WhoisInfo) {

	wi = &WhoisInfo{}
	for name, regs := range p.reg {
		switch name {
		case DomainName:
			for _, reg := range regs {
				value := reg.FindSubmatch(data)
				if len(value) == 2 {
					wi.DomainName = strings.ToLower(string(value[1]))
				}
			}
		case NameServers:
			wi.NameServers = []string{}
			for _, reg := range regs {
				values := reg.FindAllSubmatch(data, -1)
				for _, v := range values {
					if len(v) == 2 {
						wi.NameServers = append(wi.NameServers, string(v[1]))
					}
				}
			}
		case Org:
			for _, reg := range regs {
				value := reg.FindSubmatch(data)
				if len(value) == 2 {
					wi.Org = strings.ToLower(string(value[1]))
				}
			}
		case Refer:
			for _, reg := range regs {
				value := reg.FindSubmatch(data)
				if len(value) == 2 {
					wi.Refer = strings.ToLower(string(value[1]))
				}
			}
		case Error:
			for _, reg := range regs {
				value := reg.Find(data)
				if len(value) != 0 {
					wi.Error = string(value)
				}
			}
		}
	}

	return wi
}

type WhoisInfo struct {
	DomainName  string
	NameServers []string
	Org         string
	Refer      string
	Error      string
}




/*
				   'domain_name': 'domain: *(.+)',
			'registrar': 'registrar: *(.+)',
			'creation_date': 'created: *(.+)',
			'expiration_date': 'paid-till: *(.+)',
			'updated_date': None,
			'name_servers': 'nserver: *(.+)',  # list of name servers
			'status': 'state: *(.+)',  # list of statuses
			'emails': EMAIL_REGEX,  # list of email addresses
			'org': 'org: *(.+)'
*/

//func NewDefaultParse() *Parser {
//	return &Parser{reg: map[string]*regexp.Regexp{
//		`domain_name`:     regexp.MustCompile(`Domain Name`),
//		`registrar`:       regexp.MustCompile(`Registrar: *(.+)`),
//		`whois_server`:    regexp.MustCompile(`Whois Server: *(.+)`),
//		`referral_url`:    regexp.MustCompile(`Referral URL: *(.+)`),
//		`updated_date`:    regexp.MustCompile(`Updated Date: *(.+)`),
//		`creation_date`:   regexp.MustCompile(`Creation Date: *(.+`),
//		`expiration_date`: regexp.MustCompile(`Expir\w+ Date: *(.+)`),
//		`name_servers`:    regexp.MustCompile(`Name Server: *(.+)`),
//		`status`:          regexp.MustCompile(`Status: *(.+)`),
//		`dnssec`:          regexp.MustCompile(`dnssec: *([\S]+)`),
//		`name`:            regexp.MustCompile(`Registrant Name: *(.+)`),
//		`org`:             regexp.MustCompile(`Registrant\s*Organization: *(.+)`),
//		`address`:         regexp.MustCompile(`Registrant Street: *(.+)`),
//		`city`:            regexp.MustCompile(`Registrant City: *(.+)`),
//		`state`:           regexp.MustCompile(`Registrant State/Province: *(.+)`),
//		`zipcode`:         regexp.MustCompile(`Registrant Postal Code: *(.+)`),
//		`country`:         regexp.MustCompile(`Registrant Country: *(.+)`),
//	}}
//}