## Prerequisites
Make sure you have built the Docker images as mentioned in [the specified section](https://github.com/Networks-it-uc3m/netconf-sdn-controller/tree/66df380e12220a09943c60562a53e19cd69ce6ed/build)).

## Step 1
Start the Docker containers using Docker Compose:
```shell
docker-compose up
```
## Step 2
Apply the network configuration to ensure ONOS recognizes the devices:
```shell
curl -X POST -H "content-type:application/json" \
http://localhost:8181/onos/v1/network/configuration \
-d @netconf-cfg.json --user onos:rocks
```
## Step 3
Add security configuration to ONOS:
```shell
curl --location 'http://localhost:8181/onos/ccipstest-app/sample/edit-netconf' \
-H "Content-Type: application/json" \
-d '{
  "ipData1": "172.20.0.2",
  "ipControl1": "172.20.0.2",
  "ipData2": "172.20.0.3",
  "ipControl2": "172.20.0.3",
  "encAlg": "des-cbc",
  "intalg": "md5",
  "nBytesSoft": "1000000",
  "nPacketsSoft": "10000",
  "nTimeSoft": "30",
  "nTimeIdleSoft": "100000",
  "nBytesHard": "20000000000",
  "nPacketsHard": "200000000",
  "nTimeHard": "3000000",
  "nTimeIdleHard": "12000"
}' --user onos:rocks
```
## Step 4
Monitor traffic on Router A:
```shell
docker exec -it router-a bash
tcpdump
```
## Step 5
Test connectivity from Router B by pinging Router A:
```shell
docker exec -it router-b bash
ping 172.20.0.2
```
