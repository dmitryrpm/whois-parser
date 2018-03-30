package parser

import (
	uglyParser "github.com/dmitryrpm/whois-parser-go"
)

func NewUglyParser() Interface {
	return &UglyParser{}
}

type UglyParser struct {}

func (p *UglyParser) Parse(data []byte) (wi *WhoisInfo) {
	// TODO try autocheck type whois Server

	// do ugly parsing
	d, _ := uglyParser.Parse(string(data))
	return p.convertData(d)
}

func (p *UglyParser) convertData (info uglyParser.WhoisInfo) (wi *WhoisInfo) {
	return &WhoisInfo{}
}
