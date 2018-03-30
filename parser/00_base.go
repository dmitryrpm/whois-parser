package parser

const (
	DomainName = iota
	NameServers
	Org
	Refer
	Error
)

var whoisMap = map[string]func() Interface{
	`whois.tcinet.ru`: NewTcinetRuParser,
	`whois.iana.org`: NewIana,
}

type WhoisInfo struct {
	DomainName  string
	NameServers []string
	Org         string
	Refer      string
	Error      string
}

