# whois-wrapper

There are various nodejs whois clients. All of them do too many elaborated things and none good.

This is not a whois client, this is just a wrapper around the whois client installed on your OS. There is nothing more
reliable than the CLI whois client.

Only tested on mac and linux.

### Prerequisites

You need whois. E.g.,`apt-get install whois`

### Usage

```js
import whois from "whois-wrapper";

whois({query: "181.64.132.0/24"})
    .then(console.log)
    .catch(console.log)
```

Answer:

```json
[
  {
    "server": "whois.ripe.net",
    "data": [
      [
        {
          "key": "inetnum",
          "value": "83.231.214.0 - 83.231.214.255"
        },
        {
          "key": "netname",
          "value": "VERIO-DE-INFRA"
        },
        {
          "key": "country",
          "value": "DE"
        },
        {
          "key": "admin-c",
          "value": "NERA4-RIPE"
        },
        {
          "key": "remarks",
          "value": [
            "INFRA-AW",
            "Abuse/UCE:abuse@us.ntt.net",
            "Network:noc@us.ntt.net",
            "Security issues:security@us.ntt.net",
            "Geofeed https://geo.ip.gin.ntt.net/geofeeds/geofeeds.csv"
          ]
        },
        {
          "key": "descr",
          "value": [
            "NTTEO DE frankfurt facility"
          ]
        }
      ],
      [
        {
          "key": "role",
          "value": "NTT IP Addressing"
        },
        {
          "key": "address",
          "value": "5680 Greenwood Plaza Blvd."
        },
        {
          "key": "address",
          "value": "Greenwood Village, CO 80111"
        },
        {
          "key": "address",
          "value": "United States"
        }
      ]
    ]
  }
]
```

### Options

| Option  | Meaning                                                                                     | Default    |
|---------|---------------------------------------------------------------------------------------------|------------|
| query   | The whois query. Read `man whois` for information. E.g., `"r > 103.13.80.0/22"`             |            |
| flag    | The flag to select the server. Usually `s` or `h`, depending on the os.                     |            |
| servers | The array of whois servers.                                                                 | All 5 RIRs |
| timeout | Timeout for the whois command.                                                              | 4000       |
| fields  | An array of whois fields (strings) you would like to receive. E.g., `["inetnum", "inet6num"]` | All fields |
