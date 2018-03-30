package parser

import "regexp"

func NewTcinetRuParser() Interface {
	return &Parser{reg: map[int][]*regexp.Regexp{
		DomainName:  {regexp.MustCompile(`domain: *(.+)`)},
		NameServers: {regexp.MustCompile(`nserver: *(.+)`)},
		Org:         {regexp.MustCompile(`org: *(.+)`)},
	}}
}

