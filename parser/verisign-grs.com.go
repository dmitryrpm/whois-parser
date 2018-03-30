package parser

import "regexp"

func NewVGParser() Interface {
	return &Parser{
		err: map[string]error{
			`No match for`: NotFoundError,
		},
		reg: map[int]*regexp.Regexp{
			Error: regexp.MustCompile(`No match for`),

			// Base regexps
			DomainName:     regexp.MustCompile(`(?i)Domain Name: *(.+)`),
			NameServers:    regexp.MustCompile(`(?i)Name Server: *(.+)`),
			CreationDate:   regexp.MustCompile(`(?i)Creation Date: *(.+)`),
			UpdatedDate:    regexp.MustCompile(`(?i)Updated Date: *(.+)`),
			ExpirationDate: regexp.MustCompile(`(?i)Expir\w+ Date: *(.+)`),
			Status:         regexp.MustCompile(`(?i)Status: *(.+)`),

			// Registrar regexps
			Registrar:             regexp.MustCompile(`(?i)Registrar: *(.+)`),
			RegistrarWhoisServer:  regexp.MustCompile(`(?i)Whois Server: *(.+)`),
			RegistrarReferralUrl:  regexp.MustCompile(`(?i)Referral URL: *(.+)`),
			RegistrarOrganization: regexp.MustCompile(`(?i)Registrar: (.+)`),
			RegistrarEmail:        regexp.MustCompile(`(?i)Registrar.* Email: (.+)`),
			RegistrarPhone:        regexp.MustCompile(`(?i)Registrar.* Phone: (.+)`),
			RegistrarIanaID:       regexp.MustCompile(`(?i)Registrar.*ID: (\d+)`),
			RegistrarURL:          regexp.MustCompile(`(?i)Registrar.*URL: (.+)`),

			// Registrant regexps
			RegistrantName:         regexp.MustCompile(`(?i)Registrant Name: *(.+)`),
			RegistrantOrganization: regexp.MustCompile(`(?i)Registrant\s*Organization: *(.+)`),
			RegistrantAddress:      regexp.MustCompile(`(?i)Registrant Street: *(.+)`),
			RegistrantCity:         regexp.MustCompile(`(?i)Registrant City: *(.+)`),
			RegistrantState:        regexp.MustCompile(`(?i)Registrant State/Province: *(.+)`),
			RegistrantZipCode:      regexp.MustCompile(`(?i)Registrant Postal Code: *(.+)`),
			RegistrantCountry:      regexp.MustCompile(`(?i)Registrant Country: *(.+)`),
			RegistrantEmail:        regexp.MustCompile(`(?i)Registrant.*Email: (.+)`),
			RegistrantPhone:        regexp.MustCompile(`(?i)Registrant.*Fax: (.+)`),
			RegistrantFax:          regexp.MustCompile(`(?i)Registrant.*Phone: (.+)`),
			// Admin regexps
			// Tech regexps

		}}
}

/*

   'emails':               EMAIL_REGEX,  # list of email s
   'dnssec':               'dnssec: *([\S]+)',

*/
