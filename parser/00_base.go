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
	WhoisServer  string `json:"whois_server,omitempty"`
	URL          string `json:"url,omitempty"`
	IanaID       int64  `json:"iana_id,omitempty"`
	Email        string `json:"email,omitempty"`
	Phone        string `json:"phone,omitempty"`
	Organization string `json:"organization,omitempty"`
}

type WhoisRegistrant struct {
	Name         string `json:"name,omitempty"`
	Organization string `json:"organization,omitempty"`
	Address      string `json:"address,omitempty"`
	City         string `json:"city,omitempty"`
	State        string `json:"state,omitempty"`
	ZipCode      string `json:"zip_code,omitempty"`
	Country      string `json:"country,omitempty"`
	Phone        string `json:"phone,omitempty"`
	Fax          string `json:"fax,omitempty"`
	Email        string `json:"email,omitempty"`
}

type WhoisInfo struct {
	DomainName     string   `json:"dommain_name,omitempty"`
	NameServers    []string `json:"name_servers,omitempty"`
	CreationDate   string   `json:"create_date,omitempty"`
	UpdatedDate    string   `json:"update_date,omitempty"`
	ExpirationDate string   `json:"expiration_date,omitempty"`

	Registrar  WhoisRegistrar  `json:"registrar,omitempty"`
	Registrant WhoisRegistrant `json:"registrant,omitempty"`

	Status      []string `json:"status,omitempty"`
	Refer       string   `json:"refer,omitempty"`
	Error       error    `json:"error,omitempty"`
	ReferralUrl string   `json:"referral_url,omitempty"`
}
