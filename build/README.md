#Onos
docker build -t onos_ccips:2.7.0 .

sudo docker run --network=custom_bridge -p 8181:8181 -p 6640:6640 -p 8101:8101 -p 6633:6633 -p 6653:6653 -p 9876:9876 onos_ccips:2.7.0


#New Netopeer2
docker build -t juancarlosvillenmolina/netopeer2:1.0.0 .
docker push juancarlosvillenmolina/netopeer2:1.0.0


#Standalone Agent from new Netopeer2
- Changes: Makefile, ; in utils.c and Dockerfile
- Create network1,network2 and custom_bridge...

docker build -t agentspirs1:1.0.0 .
docker build -t agentspirs2:1.0.0 .
docker-compose up




#Add netconf devices (agents)
curl -X POST -H "content-type:application/json" http://localhost:8181/onos/v1/network/configuration -d @netconf-cfg.json --user onos:rocks

##H2H
#Create tunnel
curl --location 'http://localhost:8181/onos/ccipstest-app/sample/edit-netconf' -H "Content-Type: application/json" -d '{"ipData1": "172.20.0.2", "ipControl1": "172.20.0.2","ipData2": "172.20.0.3", "ipControl2": "172.20.0.3", "encAlg": "des-cbc", "intalg": "md5", "nBytesSoft": "1000000", "nPacketsSoft": "10000", "nTimeSoft": "30", "nTimeIdleSoft": "100000", "nBytesHard": "20000000000", "nPacketsHard": "200000000", "nTimeHard": "3000000", "nTimeIdleHard": "12000"}' --user onos:rocks

#Manual rekey 
curl -X POST 'http://localhost:8181/onos/ccipstest-app/sample/reek1' --user onos:rocks
curl -X POST 'http://localhost:8181/onos/ccipstest-app/sample/reek2' --user onos:rocks


#Tunnel test
docker exec -it agentspirs1 bash
apt install iputils-ping
ping [ip_agentspirs2]

docker exec -it agentspirs2 bash
apt install tcpdump


