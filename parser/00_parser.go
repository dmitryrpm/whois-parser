package parser

import (
	"regexp"
	"strconv"
	"strings"
)

type Interface interface {
	Parse(data []byte) (wi *WhoisInfo)
}

func New(whois string) Interface {
	v, ok := whoisMap[whois]
	if !ok {
		return NewVGParser()
	}
	return v()
}

type Parser struct {
	reg map[int]*regexp.Regexp
	err map[string]error
}

func (p *Parser) Parse(data []byte) (wi *WhoisInfo) {

	wi = &WhoisInfo{}
	for name, reg := range p.reg {
		switch name {
		case DomainName:
			value := reg.FindSubmatch(data)
			if len(value) == 2 {
				wi.DomainName = strings.TrimSpace(strings.ToLower(string(value[1])))
			}
		case NameServers:
			wi.NameServers = []string{}
			values := reg.FindAllSubmatch(data, -1)
			for _, v := range values {
				if len(v) == 2 {
					wi.NameServers = append(wi.NameServers, strings.TrimSpace(string(v[1])))
				}
			}
		case Status:
			wi.Status = []string{}
			values := reg.FindAllSubmatch(data, -1)
			for _, v := range values {
				if len(v) == 2 {
					wi.Status = append(wi.Status, strings.TrimSpace(string(v[1])))
				}
			}
		case ExpirationDate:
			value := reg.FindSubmatch(data)
			if len(value) == 2 {
				wi.ExpirationDate = strings.TrimSpace(string(value[1]))
			}
		case UpdatedDate:
			value := reg.FindSubmatch(data)
			if len(value) == 2 {
				wi.UpdatedDate = strings.TrimSpace(string(value[1]))
			}
		case CreationDate:
			value := reg.FindSubmatch(data)
			if len(value) == 2 {
				wi.CreationDate = strings.TrimSpace(string(value[1]))
			}

		// Registrar
		case RegistrarWhoisServer:
			value := reg.FindSubmatch(data)
			if len(value) == 2 {
				wi.Registrar.WhoisServer = strings.TrimSpace(string(value[1]))
			}
		case RegistrarReferralUrl:
			value := reg.FindSubmatch(data)
			if len(value) == 2 {
				wi.ReferralUrl = strings.TrimSpace(string(value[1]))
			}
		case RegistrarOrganization:
			value := reg.FindSubmatch(data)
			if len(value) == 2 {
				wi.Registrar.Organization = strings.TrimSpace(string(value[1]))
			}
		case RegistrarEmail:
			value := reg.FindSubmatch(data)
			if len(value) == 2 {
				wi.Registrar.Email = strings.TrimSpace(string(value[1]))
			}
		case RegistrarPhone:
			value := reg.FindSubmatch(data)
			if len(value) == 2 {
				wi.Registrar.Phone = strings.TrimSpace(string(value[1]))
			}
		case RegistrarIanaID:
			value := reg.FindSubmatch(data)
			if len(value) == 2 {
				wi.Registrar.IanaID, _ = strconv.ParseInt(string(value[1]), 10, 0)
			}
		case RegistrarURL:
			value := reg.FindSubmatch(data)
			if len(value) == 2 {
				wi.Registrar.URL = strings.TrimSpace(string(value[1]))
			}

		// Registrant
		case RegistrantName:
			value := reg.FindSubmatch(data)
			if len(value) == 2 {
				wi.Registrant.Name = strings.TrimSpace(string(value[1]))
			}
		case RegistrantOrganization:
			value := reg.FindSubmatch(data)
			if len(value) == 2 {
				wi.Registrant.Organization = strings.TrimSpace(string(value[1]))
			}
		case RegistrantAddress:
			value := reg.FindSubmatch(data)
			if len(value) == 2 {
				wi.Registrant.Address = strings.TrimSpace(string(value[1]))
			}
		case RegistrantCity:
			value := reg.FindSubmatch(data)
			if len(value) == 2 {
				wi.Registrant.City = strings.TrimSpace(string(value[1]))
			}
		case RegistrantState:
			value := reg.FindSubmatch(data)
			if len(value) == 2 {
				wi.Registrant.State = strings.TrimSpace(string(value[1]))
			}
		case RegistrantZipCode:
			value := reg.FindSubmatch(data)
			if len(value) == 2 {
				wi.Registrant.ZipCode = strings.TrimSpace(string(value[1]))
			}
		case RegistrantCountry:
			value := reg.FindSubmatch(data)
			if len(value) == 2 {
				wi.Registrant.Country = strings.TrimSpace(string(value[1]))
			}
		case RegistrantPhone:
			value := reg.FindSubmatch(data)
			if len(value) == 2 {
				wi.Registrant.Phone = strings.TrimSpace(string(value[1]))
			}
		case RegistrantFax:
			value := reg.FindSubmatch(data)
			if len(value) == 2 {
				wi.Registrant.Fax = strings.TrimSpace(string(value[1]))
			}
		case RegistrantEmail:
			value := reg.FindSubmatch(data)
			if len(value) == 2 {
				wi.Registrant.Email = strings.TrimSpace(string(value[1]))
			}

		case Refer:
			value := reg.FindSubmatch(data)
			if len(value) == 2 {
				wi.Refer = strings.TrimSpace(strings.ToLower(string(value[1])))
			}
		case Error:
			value := reg.Find(data)
			if len(value) != 0 {
				var ok bool
				wi.Error, ok = p.err[string(value)]
				if !ok {
					wi.Error = UnknownError
				}
			}
		}
	}

	return wi
}
