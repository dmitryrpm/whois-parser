package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"strings"
	"time"

	"os"

	"github.com/dmitryrpm/whois-parser/parser"
	"github.com/hokaccha/go-prettyjson"
)

func main() {
	domain := os.Args[1]
	log.Printf("get info for domain: %s", domain)
	jsonBytes, err := ioutil.ReadFile("./data/tld/tld.json")
	if err != nil {
		log.Fatal(err)
	}

	var f map[string]map[string]string
	err = json.Unmarshal(jsonBytes, &f)
	if err != nil {
		fmt.Println("Error parsing JSON: ", err)
	}

	found := ""
	for k := range f {
		if strings.HasSuffix(domain, "."+k) {
			if len(found) < len(k) {
				found = k
			}
		}
	}

	whoisServer, ok := f[found]["host"]
	if !ok {
		log.Fatal("not found whois service for host")
	}
	log.Printf("found whois server: %#v", whoisServer)

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
