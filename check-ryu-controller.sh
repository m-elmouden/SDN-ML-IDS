#!/bin/bash

echo "Checking Ryu controller status..."

# Check if the container is running
echo "Container status:"
docker ps | grep ryu-controller-custom

# Check the container's logs
echo -e "\nContainer logs:"
docker logs ryu-controller-custom

# Check if the ports are listening
echo -e "\nListening ports in the controller container:"
docker exec ryu-controller-custom netstat -tulpn | grep -E '6653|8080'

# Try to connect to the controller from Mininet
echo -e "\nTrying to connect to the controller from Mininet:"
docker exec mininet nc -zv ryu-controller-custom 6653

echo -e "\nNetwork information:"
docker network inspect sdn-network
