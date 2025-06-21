#!/bin/bash

# Wait for Ryu controller to be ready
echo "Waiting for Ryu controller to be ready..."
until nc -z ryu-controller-custom 6653; do
  echo "Ryu controller is not ready yet..."
  sleep 2
done
echo "Ryu controller is ready!"

# Run the Mininet topology
python -u /mininet/custom/topo.py
