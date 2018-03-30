package parser

import "errors"

const (
	DomainName = iota
	NameServers
	CreationDate
	UpdatedDate
	ExpirationDate
	Status

	// Registrar
	RegistrarWhoisServer
	RegistrarReferralUrl
	RegistrarURL
	RegistrarOrganization
	RegistrarPhone
	RegistrarEmail
	RegistrarIanaID

	// Registrant
	RegistrantName
	RegistrantOrganization
	RegistrantAddress
	RegistrantCity
	RegistrantState
	RegistrantZipCode
	RegistrantCountry
	RegistrantPhone
	RegistrantFax
	RegistrantEmail

	Refer
	Error
	Registrar
)

var ValidateError = errors.New("incorrect domain name")
var NotFoundError = errors.New("does not exist")
var UnknownError = errors.New("unknown error")

var whoisMap = map[string]func() Interface{
	// iana
	`whois.iana.org`: NewIana,
	// .ru
	`whois.tcinet.ru`: NewTcinetRuParser,
	// .com
	`whois.verisign-grs.com`: NewVGParser,
	`whois.markmonitor.com`:  NewVGParser,
	`whois.safenames.net`:    NewVGParser,
}

type WhoisRegistrar struct {
	WhoisServer  string
	URL          string
	IanaID       int64
	Email        string
	Phone        string
	Organization string
}

type WhoisRegistrant struct {
	Name         string
	Organization string
	Address      string
	City         string
	State        string
	ZipCode      string
	Country      string
	Phone        string
	Fax          string
	Email        string
}

type WhoisInfo struct {
	DomainName     string   `json:"dommain_name,omitempty"`
	NameServers    []string `json:"name_servers,omitempty"`
	CreationDate   string   `json:"create_date,omitempty"`
	UpdatedDate    string   `json:"update_date,omitempty"`
	ExpirationDate string   `json:"expiration_date,omitempty"`

	Registrar  WhoisRegistrar
	Registrant WhoisRegistrant

	Status      []string `json:"status,omitempty"`
	Refer       string   `json:"refer,omitempty"`
	Error       error    `json:"error,omitempty"`
	ReferralUrl string   `json:"referral_url,omitempty"`
}
