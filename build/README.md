
# Onos

### Build the Onos Docker image
To build the ONOS Docker image, use the following command:
```bash
docker build -t onos_ccips:latest .
```

# Standalone Agent from New Netopeer2
## New Netopeer2
You do not need to build the Netopeer2 image yourself. The agent will automatically pull the necessary image from Docker Hub. However, the following steps are provided to document how the image was built and made available on Docker Hub.
### Build the Netopeer2 Docker image
To understand the process, here’s how the Netopeer2 image was built:
```bash
docker build -t juancarlosvillenmolina/netopeer2:1.0.0 .
```

### Push the image to Docker Hub
The image was then pushed to Docker Hub with the following command:
```bash
docker push juancarlosvillenmolina/netopeer2:1.0.0
```
## Build agent images
To build the new agent images, based on the Netopeer2 image from Docker Hub, use the following command:
```bash
docker build -t agent:latest .
```

