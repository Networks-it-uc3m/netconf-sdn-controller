
# Onos

### Build the Onos Docker image
```bash
docker build -t onos_ccips:2.7.0 .
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

### Build agent images
```bash
docker build -t agentspirs:1.0.0 .
```

