package parser

import "regexp"

var I = WhoisInfo{}

func NewIana() Interface {
	return &Parser{reg: map[int][]*regexp.Regexp{
		DomainName:  {regexp.MustCompile(`domain: *(.+)`)},
		NameServers: {regexp.MustCompile(`nserver: *(.+)`)},
		Org:         {regexp.MustCompile(`org: *(.+)`)},
		Refer:       {regexp.MustCompile(`refer: *(.+)`)},
		Error:       {
			regexp.MustCompile(`This query returned 0 objects`),
			regexp.MustCompile(`Invalid query .*`)},
	}}
}
