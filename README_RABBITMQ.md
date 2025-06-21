# RabbitMQ-based IDS System

This system converts the original Kafka-based IDS (Intrusion Detection System) to use RabbitMQ as the message broker. The system consists of:

1. **RabbitMQ Message Broker** - Handles feature and decision message routing
2. **Ryu SDN Controller** - Extracts network features and publishes to RabbitMQ
3. **ML Consumer** - Processes features and publishes attack decisions
4. **ML Model API** - Provides machine learning predictions
5. **Dashboard** - Web interface for monitoring decisions
6. **Mininet** - Network simulation environment

## Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Ryu SDN       │    │    RabbitMQ     │    │  ML Consumer    │
│   Controller    │───▶│   (features)    │───▶│   (Python 3)    │
│  (Python 2.7)   │    │                 │    │                 │
└─────────────────┘    │   (decisions)   │    └─────────────────┘
         ▲              │                 │             │
         │              └─────────────────┘             │
         │                       │                      ▼
┌─────────────────┐              │              ┌─────────────────┐
│    Mininet      │              │              │   ML Model API  │
│   (Network)     │              │              │  (Python 3.8)   │
└─────────────────┘              ▼              └─────────────────┘
                          ┌─────────────────┐
                          │    Dashboard    │
                          │   (Node.js)     │
                          └─────────────────┘
```

## Quick Start

### Prerequisites

- Docker and Docker Compose installed
- At least 4GB RAM available
- Ports 5672, 15672, 6653, 8080, 5000, 9000 available

### Linux/macOS

```bash
# Clone and navigate to the project
cd seetupforLinux

# Start the system
chmod +x start_rabbitmq_system.sh
./start_rabbitmq_system.sh
```

### Windows

```powershell
# Navigate to the project
cd seetupforLinux

# Start the system
.\start_rabbitmq_system.ps1
```

## System Components

### 1. RabbitMQ Message Broker

- **Image**: `rabbitmq:3.12-management`
- **Ports**: 5672 (AMQP), 15672 (Management UI)
- **Queues**: `features`, `decisions`
- **Credentials**: guest/guest

### 2. Ryu SDN Controller (Python 2.7)

- **File**: `ryu_app/enhanced_ids_rabbitmq.py`
- **Function**: Network packet analysis and feature extraction
- **Dependencies**: pika, numpy, websocket-client
- **Features**:
  - Extracts 33 network features from 100-packet windows
  - Publishes features to RabbitMQ `features` queue
  - Consumes decisions from RabbitMQ `decisions` queue
  - WebSocket connection to dashboard

### 3. ML Consumer (Python 3.9)

- **File**: `ml_model/ml_consumer_rabbitmq.py`
- **Function**: Feature processing and ML prediction coordination
- **Dependencies**: pika, requests, numpy
- **Process**:
  1. Consumes features from `features` queue
  2. Calls ML Model API for predictions
  3. Publishes decisions to `decisions` queue

### 4. ML Model API (Python 3.8)

- **File**: `ml_model/model_server_2.py`
- **Port**: 5000
- **Endpoints**:
  - `GET /health` - Health check
  - `POST /predict` - Feature prediction
- **Models**: XGBoost-based binary classification

### 5. Dashboard (Node.js)

- **File**: `dashboard/server_rabbitmq.js`
- **Port**: 8080
- **Function**: Real-time decision visualization
- **Dependencies**: ws, amqplib
- **Features**:
  - Consumes decisions from RabbitMQ
  - WebSocket server for real-time updates
  - Built-in web interface

## Configuration

### Environment Variables

#### Ryu Controller
```bash
RABBITMQ_URL=amqp://guest:guest@rabbitmq:5672/
FEATURES_QUEUE=features
DECISIONS_QUEUE=decisions
DASHBOARD_WS_URL=ws://dashboard:8080/ws
WINDOW_SIZE=100
```

#### ML Consumer
```bash
RABBITMQ_URL=amqp://guest:guest@rabbitmq:5672/
FEATURES_QUEUE=features
DECISIONS_QUEUE=decisions
ML_API_URL=http://ml-model:5000/predict
ML_HEALTH_URL=http://ml-model:5000/health
LOG_LEVEL=INFO
```

#### Dashboard
```bash
RABBITMQ_URL=amqp://guest:guest@rabbitmq:5672/
DECISIONS_QUEUE=decisions
PORT=8080
LOG_LEVEL=info
```

## Access Points

Once the system is running:

- **RabbitMQ Management**: http://localhost:15672 (guest/guest)
- **Dashboard**: http://localhost:8080
- **ML Model API**: http://localhost:5000
- **Portainer**: http://localhost:9000

## Message Formats

### Features Message (Ryu → ML Consumer)
```json
{
  "flow_id": "192.168.1.1:80-192.168.1.2:12345-6",
  "timestamp": 1672531200.123,
  "features": [0.1, 6, 64, 10.5, ...],
  "window_size": 100
}
```

### Decision Message (ML Consumer → Dashboard)
```json
{
  "flow_id": "192.168.1.1:80-192.168.1.2:12345-6",
  "timestamp": 1672531201.456,
  "original_timestamp": 1672531200.123,
  "is_attack": false,
  "attack_type": 0,
  "confidence": 0.95,
  "model_status": "success",
  "processing_time": 1.333,
  "source": "ml_consumer_rabbitmq"
}
```

## Network Features (33 total)

1. **flow_duration** - Time between first and last packet
2. **Protocol_Type** - Most common protocol (6=TCP, 17=UDP, 1=ICMP)
3. **Duration** - TTL value
4. **Rate** - Overall packet transmission rate
5. **Drate** - Inbound packet transmission rate
6-11. **TCP Flags** - Binary flags (FIN, SYN, RST, PSH, ACK, ECE, CWR)
12-15. **Flag Counts** - ACK, SYN, FIN, URG counts
16-22. **Application Protocols** - HTTP, HTTPS, DNS, Telnet, SMTP, SSH, IRC
23-29. **Network Protocols** - TCP, UDP, DHCP, ARP, ICMP, IPv, LLC
30. **Tot_sum** - Sum of packet sizes
31. **IAT** - Mean inter-arrival time
32. **Number** - Number of packets in window

## Troubleshooting

### Common Issues

1. **RabbitMQ Connection Failed**
   ```bash
   # Check RabbitMQ logs
   docker-compose -f docker-compose-rabbitmq.yml logs rabbitmq
   
   # Restart RabbitMQ
   docker-compose -f docker-compose-rabbitmq.yml restart rabbitmq
   ```

2. **ML Model Not Ready**
   ```bash
   # Check model health
   curl http://localhost:5000/health
   
   # Check model logs
   docker-compose -f docker-compose-rabbitmq.yml logs ml-model
   ```

3. **Dashboard Not Receiving Messages**
   ```bash
   # Check dashboard logs
   docker-compose -f docker-compose-rabbitmq.yml logs dashboard
   
   # Check RabbitMQ queues in management UI
   # http://localhost:15672/#/queues
   ```

4. **Python 2.7 Compatibility Issues**
   - Ensure all string operations use `.format()` instead of f-strings
   - Use `print()` function syntax
   - Handle unicode/bytes properly

### Performance Tuning

1. **RabbitMQ Performance**
   ```bash
   # Increase queue prefetch
   RABBITMQ_DEFAULT_VHOST_LIMITS='{"max-connections":1000,"max-queues":1000}'
   ```

2. **ML Consumer Scaling**
   ```bash
   # Scale ML consumer instances
   docker-compose -f docker-compose-rabbitmq.yml up -d --scale ml-consumer=3
   ```

### Monitoring

1. **RabbitMQ Metrics**
   - Queue lengths and rates
   - Connection counts
   - Memory and disk usage

2. **System Metrics**
   ```bash
   # Check container stats
   docker stats
   
   # Check system resource usage
   docker-compose -f docker-compose-rabbitmq.yml top
   ```

## Migration from Kafka

Key differences from the Kafka version:

1. **Message Broker**: RabbitMQ instead of Kafka+Zookeeper
2. **Client Libraries**: 
   - Ryu: `pika` instead of `kafka-python`
   - ML Consumer: `pika` instead of `kafka-python`
   - Dashboard: `amqplib` instead of `kafkajs`
3. **Message Routing**: Direct queue routing instead of topic partitioning
4. **Connection Management**: AMQP connection pooling
5. **Queue Durability**: Persistent queues instead of topic replication

## Security Considerations

1. **Default Credentials**: Change default guest/guest for production
2. **Network Security**: Use proper firewall rules
3. **TLS/SSL**: Enable for production deployments
4. **Authentication**: Consider LDAP/OAuth integration for RabbitMQ

## Development

### Testing Individual Components

```bash
# Test Ryu controller only
docker-compose -f docker-compose-rabbitmq.yml up rabbitmq ryu-controller-custom

# Test ML pipeline only
docker-compose -f docker-compose-rabbitmq.yml up rabbitmq ml-model ml-consumer

# Test dashboard only
docker-compose -f docker-compose-rabbitmq.yml up rabbitmq dashboard
```

### Code Structure

```
seetupforLinux/
├── docker-compose-rabbitmq.yml     # Main compose file
├── ryu_app/
│   └── enhanced_ids_rabbitmq.py    # Ryu controller (Python 2.7)
├── ml_model/
│   ├── ml_consumer_rabbitmq.py     # ML consumer (Python 3.9)
│   └── model_server_2.py           # ML API server
├── dashboard/
│   └── server_rabbitmq.js          # Dashboard server (Node.js)
├── start_rabbitmq_system.sh        # Linux startup script
├── start_rabbitmq_system.ps1       # Windows startup script
└── README_RABBITMQ.md             # This file
```
