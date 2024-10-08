#!/bin/bash

# turn on bash's job control
set -m

# Start the onos server and put it on the background
./bin/onos-service server &

sleep 10

while true; do
    response=$(wget --spider --server-response http://localhost:8181/onos/ui 2>&1)
    status_codes=$(echo "$response" | awk '/HTTP\/1.1/{print $2}')

    if echo "$status_codes" | grep -q "200"; then
        echo "Starting the configuration"
        break
    fi

    sleep 10
done


# Start the configuration
./onos_critique.sh

./bin/onos-app localhost activate org.onosproject.netconf
./bin/onos-app localhost activate org.onosproject.drivers.netconf
./bin/onos-app localhost install! ccips-app-1.0.0.oar

# now we bring the server into the foreground
fg %1
