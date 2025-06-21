# SDN Security Monitoring with Mininet

This project implements a Software-Defined Networking (SDN) security monitoring system using Mininet, Ryu controller, and machine learning for intrusion detection.

## Architecture

- **Mininet**: Network emulation platform that creates a realistic virtual network
- **Ryu Controller**: SDN controller with custom IDS application
- **ML Model**: Machine learning model for traffic classification
- **Dashboard**: Web interface for monitoring network security events

## Components

1. **Mininet Container**: Creates a virtual network with 4 hosts and 1 switch
2. **Ryu Controller**: Analyzes network traffic and makes security decisions
3. **ML Model**: Classifies traffic as normal or attack
4. **Dashboard**: Visualizes traffic patterns and security events

## Usage

### Starting the System

```bash
docker-compose up -d
```

This will start all containers including:
- Mininet with a custom topology (4 hosts connected to 1 switch)
- Ryu controller with IDS application
- ML model server
- Web dashboard

### Accessing the Dashboard

Open your browser and navigate to:
```
http://localhost:8080
```

### Interacting with Mininet

To access the Mininet CLI:

```bash
docker exec -it mininet /bin/bash
# Inside the container
python3 /root/custom_topo.py
```

Common Mininet commands:
- `h1 ping h2` - Test connectivity between hosts
- `h1 iperf -s &` - Start iperf server on h1
- `h2 iperf -c h1` - Test bandwidth between h2 and h1

## Troubleshooting

- If the controller doesn't connect, restart the Mininet container
- Check logs with `docker logs ryu-controller-custom` or `docker logs mininet`