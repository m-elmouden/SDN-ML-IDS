#!/bin/bash

# This script fixes the connection between Mininet and the Ryu controller

echo "Fixing controller connection between Mininet and Ryu..."

# Verify the Ryu controller is running
if ! docker ps | grep -q "ryu-controller-custom"; then
    echo "Error: ryu-controller-custom container is not running!"
    exit 1
fi

# Get the IP address of the Ryu controller
RYU_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' ryu-controller-custom)
echo "Ryu controller IP: $RYU_IP"

# Execute command inside the Mininet container to update the controller IP
docker exec mininet bash -c "echo 'Controller IP is $RYU_IP'"

# Check if the ovs-vsctl command is available in the Mininet container
docker exec mininet which ovs-vsctl >/dev/null 2>&1
if [ $? -ne 0 ]; then
    echo "Error: ovs-vsctl command not found in the Mininet container!"
    exit 1
fi

# Update the OpenFlow controller connection
echo "Updating the controller connection in Mininet..."
docker exec mininet ovs-vsctl set-controller s1 tcp:$RYU_IP:6653

# Verify the connection
echo "Verifying controller connection..."
docker exec mininet ovs-vsctl show

echo "Connection fix applied. Now try running the custom_topo.py script again."
