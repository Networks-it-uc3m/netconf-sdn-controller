## 1
```shell
docker-compose up
```

## 2
```shell
curl -X POST -H "content-type:application/json" http://localhost:8181/onos/v1/network/configuration -d @netconf-cfg.json --user onos:rocks
```
## 3
```shell
docker exec -it router-a bash
ip route add 192.168.1.0/24 via 172.20.0.3
tcpdump
```
## 4
```shell
docker exec -it router-b bash
ip route add 192.168.0.0/24 via 172.20.0.2
tcpdump
```
## 5
```shell
docker exec -it client-domainA sh
ping 192.168.1.100
```
## 6
```shell
curl --location 'http://localhost:8181/onos/ccipstest-app/sample/edit-netconf' -H "Content-Type: application/json" -d '{ "networkInternal1": "192.168.0.0/24","ipData1": "172.20.0.2", "ipControl1": "172.20.0.2","networkInternal2": "192.168.1.0/24", "ipData2": "172.20.0.3", "ipControl2": "172.20.0.3", "encAlg": "des-cbc", "intalg": "md5", "nBytesSoft": "0", "nPacketsSoft": "1000000", "nTimeSoft": "80", "nTimeIdleSoft": "10000", "nBytesHard": "100000", "nPacketsHard": "100000", "nTimeHard": "3000000", "nTimeIdleHard": "100000"}' --user onos:rocks
```