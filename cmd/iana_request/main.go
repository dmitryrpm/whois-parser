package main

import (
	"net"
	"time"
	"io/ioutil"
	"log"
	"github.com/dmitryrpm/whois-parser/parser"
)

func main(){
	domain := "google.com"
	// Do connect with connection timeout
	connection, err := net.DialTimeout("tcp", net.JoinHostPort("whois.iana.org", "43"), 10*time.Second)
	if err != nil {
		log.Fatalf("correct error: %s", err)
	}
	defer connection.Close()
	// need set connect duration, if whois server has
	// no answer a long time - it is worker deadlock
	connection.SetDeadline(time.Now().Add(10*time.Second))
	// Get needed adapter
	connection.Write([]byte(domain + "\r\n"))

	// Wait an answer timeout
	b, err := ioutil.ReadAll(connection)
	p := parser.New("whois.iana.org")
	parseObj := p.Parse(b)
	log.Printf("domain: %v\n", parseObj.DomainName)
	log.Printf("refer: %v\n", parseObj.Refer)
	log.Printf("count ns-name: %v\n", len(parseObj.NameServers))
}
