# whois-parser
Parse whois-information about domains

```bash
>> go get github.com/dmitryrpm/whois-parser
>> dep ensure
go run cmd/do_request/main.go
2018/03/31 02:52:14 result parse domain: [google.com], to whois server: [whois.markmonitor.com]  
```

```json
{
  "Registrant": {
    "Address": "1600 Amphitheatre Parkway, ",
    "City": "Mountain View",
    "Country": "US",
    "Email": "dns-admin@google.com",
    "Fax": "+1.6502530000",
    "Name": "Domain Administrator",
    "Organization": "Google LLC",
    "Phone": "+1.6502530001",
    "State": "CA",
    "ZipCode": "94043"
  },
  "Registrar": {
    "Email": "abusecomplaints@markmonitor.com",
    "IanaID": 292,
    "Organization": "MarkMonitor, Inc.",
    "Phone": "+1.2083895740",
    "URL": "http://www.markmonitor.com",
    "WhoisServer": "whois.markmonitor.com"
  },
  "create_date": "1997-09-15T00:00:00-0700",
  "dommain_name": "google.com",
  "expiration_date": "2020-09-13T21:00:00-0700",
  "name_servers": [
    "ns2.google.com",
    "ns4.google.com",
    "ns3.google.com",
    "ns1.google.com"
  ],
  "status": [
    "clientUpdateProhibited (https://www.icann.org/epp#clientUpdateProhibited)",
    "clientTransferProhibited (https://www.icann.org/epp#clientTransferProhibited)",
    "clientDeleteProhibited (https://www.icann.org/epp#clientDeleteProhibited)",
    "serverUpdateProhibited (https://www.icann.org/epp#serverUpdateProhibited)",
    "serverTransferProhibited (https://www.icann.org/epp#serverTransferProhibited)",
    "serverDeleteProhibited (https://www.icann.org/epp#serverDeleteProhibited)"
  ],
  "update_date": "2018-02-21T10:45:07-0800"
}
```