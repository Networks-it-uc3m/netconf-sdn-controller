##1
docker-compose up

##2
curl -X POST -H "content-type:application/json" \
http://localhost:8181/onos/v1/network/configuration \
-d @netconf-cfg.json --user onos:rocks

##3
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

##4
docker exec -it router-a bash
tcpdump
##5
docker exec -it router-b bash
ping 172.20.0.2
