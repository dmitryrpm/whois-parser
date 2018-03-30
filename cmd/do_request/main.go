package main

import (
	"io/ioutil"
	"log"
	"net"
	"time"

	"github.com/dmitryrpm/whois-parser/parser"
	prettyjson "github.com/hokaccha/go-prettyjson"
)

func main() {
	domain := "google.com"
	whoisServer := "whois.markmonitor.com"
	// Do connect with connection timeout
	connection, err := net.DialTimeout("tcp", net.JoinHostPort(whoisServer, "43"), 10*time.Second)
	if err != nil {
		log.Fatalf("correct error: %s", err)
	}
	defer connection.Close()
	// need set connect duration, if whois server has
	// no answer a long time - it is worker deadlock
	connection.SetDeadline(time.Now().Add(10 * time.Second))
	// Get needed adapter
	connection.Write([]byte(domain + "\r\n"))

	// Wait an answer timeout
	b, err := ioutil.ReadAll(connection)
	p := parser.New(whoisServer)
	parseObj := p.Parse(b)

	json, err := prettyjson.Marshal(parseObj)

	//json, err := json.MarshalIndent(parseObj, "    ", "")
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("result parse domain: [%s], to whois server: [%s] \n%s", domain, whoisServer, json)

}
