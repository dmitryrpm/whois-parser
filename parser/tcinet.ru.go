package parser

import "regexp"

func NewTcinetRuParser() Interface {
	return &Parser{reg: map[int]*regexp.Regexp{
		DomainName:            regexp.MustCompile(`domain: *(.+)`),
		NameServers:           regexp.MustCompile(`nserver: *(.+)`),
		RegistrarOrganization: regexp.MustCompile(`org: *(.+)`),
	}}
}

/*
	'registrar': 'registrar: *(.+)',
	'creation_date': 'created: *(.+)',
	'expiration_date': 'paid-till: *(.+)',
	'updated_date': None,
	'name_servers': 'nserver: *(.+)',  # list of name servers
	'status': 'state: *(.+)',  # list of statuses
	'emails': EMAIL_REGEX,  # list of email addresses
	'org': 'org: *(.+)'
*/
