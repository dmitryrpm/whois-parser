# whois-parser
Parse whois-information about domains

```bash
>> go get github.com/dmitryrpm/whois-parser
>> dep ensure
>> go run cmd/do_request/main.go google.com
   2018/04/01 01:49:23 get info for domain: google.com
   2018/04/01 01:49:23 found whois server: "whois.verisign-grs.com"
   2018/04/01 01:49:24 result parse domain: [google.com], to whois server: [whois.verisign-grs.com] 
   {
     "create_date": "1997-09-15T04:00:00Z",
     "dommain_name": "google.com",
     "expiration_date": "2020-09-14T04:00:00Z",
     "name_servers": [
       "NS1.GOOGLE.COM",
       "NS2.GOOGLE.COM",
       "NS3.GOOGLE.COM",
       "NS4.GOOGLE.COM"
     ],
     "registrant": {},
     "registrar": {
       "email": "abusecomplaints@markmonitor.com",
       "iana_id": 292,
       "organization": "MarkMonitor Inc.",
       "phone": "+1.2083895740",
       "url": "http://www.markmonitor.com",
       "whois_server": "whois.markmonitor.com"
     },
     "status": [
       "clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited",
       "clientTransferProhibited https://icann.org/epp#clientTransferProhibited",
       "clientUpdateProhibited https://icann.org/epp#clientUpdateProhibited",
       "serverDeleteProhibited https://icann.org/epp#serverDeleteProhibited",
       "serverTransferProhibited https://icann.org/epp#serverTransferProhibited",
       "serverUpdateProhibited https://icann.org/epp#serverUpdateProhibited"
     ],
     "update_date": "2018-02-21T18:36:40Z"
   }
```