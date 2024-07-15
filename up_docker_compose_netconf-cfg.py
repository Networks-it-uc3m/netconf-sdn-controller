# -*- coding: utf-8 -*-
import os
import subprocess
import time
import json
from threading import Thread
from ipaddress import ip_network, ip_address
import signal
import sys

# Increase the HTTP request timeout for Docker Compose
os.environ['COMPOSE_HTTP_TIMEOUT'] = '10000'

# Set the DOCKER_HOST environment variable if Docker is listening on a non-standard socket
os.environ['DOCKER_HOST'] = 'unix:///var/run/docker.sock'  

# Ask the user for the number of agents
agents_count = int(input("Enter the number of agents: "))

# Function to get existing Docker subnets
def get_existing_subnets():
    result = subprocess.run(['docker', 'network', 'ls', '-q'],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    if result.returncode != 0:
        return []
    network_ids = result.stdout.split()
    subnets = set()
    for network_id in network_ids:
        inspect_result = subprocess.run(['docker', 'network', 'inspect', network_id],
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
        if inspect_result.returncode == 0:
            network_info = json.loads(inspect_result.stdout)
            for network in network_info:
                if 'IPAM' in network and 'Config' in network['IPAM']:
                    for config in network['IPAM']['Config']:
                        if 'Subnet' in config:
                            subnets.add(ip_network(config['Subnet']))
    return subnets

existing_subnets = get_existing_subnets()

# Basic template for the docker-compose.yml file
docker_compose_template = """
version: '3'

services:
"""

# Function to find the next available subnet
def find_available_subnet(existing_subnets, start_network):
    subnet = start_network
    while any(subnet.overlaps(existing_subnet) for existing_subnet in existing_subnets):
        subnet = ip_network(f"{subnet.network_address + subnet.num_addresses}/24")
    existing_subnets.add(subnet)
    return subnet

# Add agents to the configuration
for i in range(1, agents_count + 1):
    network = 'network{}'.format(i)
    docker_compose_template += """
  agentspirs{}:
    image: agentspirs:1.0.0
    container_name: agentspirs{}
    cap_add:
      - ALL
    networks:
      - {}
      - custom_bridge
    stdin_open: true
    tty: true
""".format(i, i, network)

docker_compose_template += """
networks:
"""

# Add incremental network configurations
start_network = ip_network("10.100.0.0/24")
for i in range(1, agents_count + 1):
    available_subnet = find_available_subnet(existing_subnets, start_network)
    docker_compose_template += """
  network{}:
    driver: bridge
    ipam:
      config:
        - subnet: {}
""".format(i, available_subnet)

docker_compose_template += """
  custom_bridge:
    external: true
"""

# Write the docker-compose.yml file
with open('docker-compose.yml', 'w') as file:
    file.write(docker_compose_template)

print("docker-compose.yml generated successfully!")

# Function to handle the interrupt signal and clean up
def signal_handler(sig, frame):
    print('Interrupt received, stopping and removing containers...')
    subprocess.run(["docker-compose", "down"], check=True)
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

# Function to run docker-compose up
def docker_compose_up():
    subprocess.run(["docker-compose", "up", "-d"], check=True)

# Function to display logs
def show_logs():
    agent_names = [f"agentspirs{i}" for i in range(1, agents_count + 1)]
    subprocess.run(["docker-compose", "logs", "--follow"] + agent_names, check=True)

# Run docker-compose up in a subprocess
up_thread = Thread(target=docker_compose_up)
up_thread.start()

# Wait for docker-compose up to finish
up_thread.join()

# Wait some time to ensure the containers are fully up
time.sleep(20)

# Create the netconf-cfg.json file
netconf_cfg = {"devices": {}}

# Inspect each container and filter the IP of the `custom_bridge` network
for i in range(1, agents_count + 1):
    container_name = 'agentspirs{}'.format(i)
    result = subprocess.run(['docker', 'inspect', container_name],
                            stdout=subprocess.PIPE, universal_newlines=True, check=True)
    container_info = json.loads(result.stdout)
    custom_bridge_ip = None

    for network_name, network_details in container_info[0]["NetworkSettings"]["Networks"].items():
        if network_name == "custom_bridge":
            custom_bridge_ip = network_details["IPAddress"]
            break

    if custom_bridge_ip:
        device_entry = {
            "netconf:{}:830".format(custom_bridge_ip): {
                "netconf": {
                    "ip": custom_bridge_ip,
                    "port": 830,
                    "username": "netconf",
                    "password": "netconf",
                    "connect-timeout": 20,
                    "reply-timeout": 3
                },
                "basic": {
                    "driver": "netconf"
                }
            }
        }
        netconf_cfg["devices"].update(device_entry)

# Write the netconf-cfg.json file
with open('netconf-cfg.json', 'w') as file:
    json.dump(netconf_cfg, file, indent=2)

print("netconf-cfg.json created successfully!")

# Display logs in a separate subprocess
logs_thread = Thread(target=show_logs)
logs_thread.start()

# Wait for logs to finish displaying (optional)
logs_thread.join()

