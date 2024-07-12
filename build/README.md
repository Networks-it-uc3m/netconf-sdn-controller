
# Onos

### Build the Onos Docker image
```bash
docker build -t onos_ccips:2.7.0 .
```

### Run the Onos container
```bash
sudo docker run --rm --init --network=custom_bridge -p 8181:8181 -p 6640:6640 -p 8101:8101 -p 6633:6633 -p 6653:6653 -p 9876:9876 onos_ccips:2.7.0
```

# New Netopeer2

### Build the Netopeer2 Docker image
```bash
docker build -t juancarlosvillenmolina/netopeer2:1.0.0 .
```

### Push the image to Docker Hub
```bash
docker push juancarlosvillenmolina/netopeer2:1.0.0
```

# Standalone Agent from New Netopeer2

### Changes made
- CMakeLists
- utils.c (add a ;)
- Dockerfile

### Create networks and custom bridges
```bash
docker network create network1
docker network create network2
docker network create custom_bridge
```

### Build agent images
```bash
docker build -t agentspirs:1.0.0 .
```


### Option1 :generate Docker-compose, generate netconf-cfg and Bring up the agents with Docker Compose:
```bash
python3 up_docker_compose_netconf-cfg.py
```
### Option 2: Bring up the agents with Docker Compose
```bash
docker-compose up
```

# Add Netconf Devices (Agents)
```bash
curl -X POST -H "content-type:application/json" \
http://localhost:8181/onos/v1/network/configuration \
-d @netconf-cfg.json --user onos:rocks
```
### netconf-cfg.json
```json
{
  "devices": {
    "netconf:172.20.0.2:830": {
      "netconf": {
        "ip": "172.20.0.2",
        "port": 830,
        "username": "netconf",
        "password": "netconf",
        "connect-timeout": 20,
        "reply-timeout": 25

},
      "basic": {
        "driver": "netconf"
      }
},
    "netconf:172.20.0.3:830": {
      "netconf": {
        "ip": "172.20.0.3",
        "port": 830,
        "username": "netconf",
        "password": "netconf",
        "connect-timeout": 20,
        "reply-timeout": 25

},
      "basic": {
        "driver": "netconf"
      }
    }
  }
}
```


## H2H

### Create tunnel
```bash
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

### Delete Ipsec SA
```bash
curl --location 'http://localhost:8181/onos/ccipstest-app/sample/del' -H "Content-Type: application/json" -d '{"reqId":"1"}' --user onos:rocks
curl --location 'http://localhost:8181/onos/ccipstest-app/sample/del' -H "Content-Type: application/json" -d '{"name":"out/172.20.0.2/in/172.20.0.3"}' --user onos:rocks

```

# Tunnel Test

### Test connectivity between agents
```bash
docker exec -it agentspirs1 bash
```
```bash
apt install iputils-ping
```
```bash
ping [ip_agentspirs2]
```


### Capture packets with tcpdump
```bash
docker exec -it agentspirs2 bash
```
```bash
apt install tcpdump
```
