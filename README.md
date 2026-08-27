# CoreDNS Manager - Zone Editing

Includes authenticated web UI plus DNS zone management.

Supported records: A, AAAA, CNAME, MX, NS, TXT, PTR.

Zone workflow:
1. Open Zones.
2. Add `example.com`.
3. Click Edit.
4. Edit the complete zone file or add records with the form.
5. Save.
6. Validate CoreDNS from the dashboard.
7. Reload CoreDNS.

Default login: `CoreDNS Manager`

Build:
    go build -o coredns-manager main.go

Run:
    sudo ./coredns-manager

Default paths:
- CoreDNS: /usr/local/bin/coredns
- Corefile: /usr/local/etc/coredns/Corefile
- Zones: /usr/local/etc/coredns/zones/

Change the default password before production use.


## Prometheus metrics

The dashboard scrapes CoreDNS Prometheus metrics from `http://127.0.0.1:9153/metrics` by default. Override with `COREDNS_PROMETHEUS_URL`. QPS is calculated from successive cumulative request counters.
