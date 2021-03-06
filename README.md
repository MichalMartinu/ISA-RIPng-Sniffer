# ISA-RIPng-Sniffer
Project for ISA @ BUT FIT

## Sniffer RIP a RIPng zpráv
 Slouží pro odchytávání a následnou interpretaci zachycených RIP a RIPng zpráv.

### Spuštění
```
 ./myripsniffer -i <rozhraní>

 -i <rozhraní> udává, na kterém rozhraní bude odchyt paketů prováděn
 ```

### Příklad spuštění
```
 ./myripsniffer -i en0
 ```

## Podvrhávač falešných RIPng Response zpráv
 Jedná se o útočný program, který napadá směrovače a podvrhává jim falešné RIPng zprávy.

### Spuštění
```
 sudo ./myripresponse -i <rozhraní> -r <IPv6>/[16-128] {-n <IPv6>} {-m [0-16]} {-t [0-65535]}

 -i <rozhraní>:¬¬ udává, na které rozhraní bude útočný paket odeslán
 -r <IPv6>/[16-128]: je IP adresa podvrhované sítě za lomítkem číselní adresa masky sítě
 -m: následující číslo udává RIP Metriku, tedy počet hopů, implicitně 1
 -n <IPv6>: za tímto parametrem je adresa next-hopu pro podvrhávanou routu, implicitně ::
 -t: číslo udává hodnotu Router Tagu, implicitně 0
 ```

### Příklad spuštění
 ```
 sudo ./myripresponse -i eth0 -r 2001:db8:0:abcd::/64
 ```
