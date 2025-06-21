#!/bin/bash

# This script helps verify and troubleshoot Mininet and Ryu connections
# Save this file as verify_connections.sh in your mininet_scripts folder

echo "===== CHECKING HOSTS ====="
# List all containers
echo "Docker containers:"
docker ps

echo -e "\n===== CHECKING MININET ====="
# Check if Mininet is running properly
docker exec mininet ps aux | grep python

echo -e "\n===== CHECKING NETWORK CONNECTIVITY ====="
# Check network interfaces in Mininet
echo "Network interfaces in Mininet:"
docker exec mininet ifconfig -a | grep -E "eth|s1"

echo -e "\n===== CHECKING RYU CONTROLLER ====="
# Check if Ryu controller is running
echo "Ryu controller status:"
docker exec ryu-controller-custom ps aux | grep ryu-manager

echo -e "\n===== TESTING CONTROLLER CONNECTION ====="
# Test connectivity from Mininet to Ryu
echo "Ping from Mininet to Ryu:"
docker exec mininet ping -c 3 ryu-custom

# Check if OpenFlow switch is connected to controller
echo -e "\n===== CHECKING OPENFLOW CONNECTION ====="
echo "OpenFlow switch connection:"
docker exec mininet ovs-vsctl show

echo -e "\n===== MANUAL INSTRUCTIONS ====="
echo "To access the Mininet CLI, run:"
echo "docker exec -it mininet /bin/bash"
echo "Then run: python3 /root/scripts/custom_topo.py"
echo 
echo "In the Mininet CLI, try these commands:"
echo "  nodes     - Shows all nodes in the network"
echo "  links     - Shows all links in the network"
echo "  pingall   - Tests connectivity between all hosts"
echo "  h1 ping h2 - Tests connectivity between h1 and h2"
echo "  h1 ping ryu-custom - Tests connectivity to controller"
echo "  exit      - Exits the CLI"
