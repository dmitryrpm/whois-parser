package parser

import "regexp"

func NewIana() Interface {
	return &Parser{
		reg: map[int]*regexp.Regexp{
			DomainName:            regexp.MustCompile(`domain: *(.+)`),
			NameServers:           regexp.MustCompile(`nserver: *(.+)`),
			RegistrarOrganization: regexp.MustCompile(`org: *(.+)`),
			Refer: regexp.MustCompile(`refer: *(.+)`),
			Error: regexp.MustCompile(`(This query returned 0 objects|Invalid query)`)},
		err: map[string]error{
			`This query returned 0 objects`: NotFoundError,
			`Invalid query`:                 ValidateError,
		},
	}
}
