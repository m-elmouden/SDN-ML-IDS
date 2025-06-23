# Enhanced IDS System with RabbitMQ - 15 Features Version

This is a specialized version of the Enhanced Intrusion Detection System (IDS) that processes exactly 15 network features instead of the original 33 features. This version is optimized for improved performance and focuses on the most critical features for network intrusion detection.

## Features Overview

The system extracts and processes these 15 key features from network traffic:

1. **fin_flag_number** - Presence of FIN flag in TCP packets
2. **psh_flag_number** - Presence of PSH flag in TCP packets  
3. **UDP** - Presence of UDP protocol packets
4. **syn_flag_number** - Presence of SYN flag in TCP packets
5. **HTTP** - Presence of HTTP protocol traffic
6. **ICMP** - Presence of ICMP protocol packets
7. **Tot sum** - Total sum of packet sizes in the flow
8. **IAT** - Inter-arrival time between packets
9. **rst_count** - Count of RST flags
10. **Weight** - Product of incoming and outgoing packets
11. **rst_flag_number** - Presence of RST flag in TCP packets
12. **flow_duration** - Time duration between first and last packet
13. **TCP** - Presence of TCP protocol packets
14. **Rate** - Overall packet transmission rate
15. **ARP** - Presence of ARP protocol packets

## System Architecture

### Components

1. **Ryu Controller (15 Features)** (`ids_rabbit_15.py`)
   - Extracts 15 features from 100-packet windows
   - Sends features to RabbitMQ 'features' queue
   - Python 2.7 compatible

2. **ML Model Server (15 Features)** (`model_server_15.py`)
   - Flask API server optimized for 15-feature predictions
   - Uses XGBoost model trained on 15 features (`xgb_model_15.joblib`)
   - Endpoint: `/predict_15`

3. **ML Consumer (15 Features)** (`ml_consumer_15_rabbitmq.py`)
   - Consumes 15-feature vectors from RabbitMQ
   - Makes predictions using the 15-feature ML model
   - Sends decisions back to RabbitMQ

4. **Dashboard (15 Features)** (`server_15_rabbitmq.js`)
   - Web interface for monitoring 15-feature IDS decisions
   - Real-time WebSocket updates
   - Displays feature count and model information

5. **RabbitMQ Message Broker**
   - Handles feature and decision message queues
   - Management UI at http://localhost:15672

## Quick Start

### Prerequisites

- Docker and Docker Compose v2
- Linux/macOS environment
- At least 4GB RAM
- Network access for downloading Docker images

### 1. Start the 15-Feature System

```bash
# Make the startup script executable
chmod +x start_15_features_system.sh

# Start all services
./start_15_features_system.sh
```

### 2. Access the Services

- **Dashboard**: http://localhost:8080
- **RabbitMQ Management**: http://localhost:15672 (guest/guest)
- **ML Model API**: http://localhost:5000
- **Portainer**: http://localhost:9000

### 3. Test Network Traffic

```bash
# Connect to Mininet
docker exec -it mininet bash

# Run the custom topology
cd /root/scripts
python3 custom_topo.py

# In Mininet CLI:
pingall
h1 ping h2
h1 wget http://172.18.0.102
```

## API Endpoints

### ML Model Server (Port 5000)

- `GET /health` - Health check
- `POST /predict_15` - Predict using 15 features
- `GET /info` - Model information
- `POST /predict` - Legacy endpoint (redirects to predict_15)

#### Prediction Request Format

```json
{
  "features": [0, 1, 0, 1, 1, 0, 0.025, 1500, 0, 2, 1, 0, 1, 3, 40.5]
}
```

#### Prediction Response Format

```json
{
  "is_attack": false,
  "attack_type": 0,
  "confidence": 0.85,
  "model": "xgb_model_15",
  "feature_count": 15,
  "scaled": true
}
```

## Configuration

### Environment Variables

#### Ryu Controller
- `RABBITMQ_URL`: RabbitMQ connection URL
- `FEATURES_QUEUE`: Features queue name (default: 'features')
- `DECISIONS_QUEUE`: Decisions queue name (default: 'decisions')
- `WINDOW_SIZE`: Packet window size (default: 100)
- `DASHBOARD_WS_URL`: Dashboard WebSocket URL

#### ML Consumer
- `RABBITMQ_URL`: RabbitMQ connection URL
- `ML_MODEL_URL`: ML model server URL
- `MAX_RETRIES`: Maximum retry attempts
- `RETRY_DELAY`: Retry delay in seconds

#### Dashboard
- `PORT`: Dashboard port (default: 8080)
- `RABBITMQ_URL`: RabbitMQ connection URL
- `DECISIONS_QUEUE`: Decisions queue name

## File Structure

```
seetupforLinux/
├── docker-compose-15-features.yml     # Docker Compose for 15-feature system
├── start_15_features_system.sh        # Startup script for 15-feature system
├── ryu_app/
│   └── ids_rabbit_15.py              # Ryu controller (15 features)
├── ml_model/
│   ├── model_server_15.py            # ML model server (15 features)
│   ├── ml_consumer_15_rabbitmq.py    # ML consumer (15 features)
│   └── xgb_model_15.joblib          # XGBoost model for 15 features
├── dashboard/
│   └── server_15_rabbitmq.js         # Dashboard server (15 features)
├── mininet_scripts/
│   └── custom_topo.py                # Mininet topology script
└── README_15_FEATURES.md             # This file
```

## Monitoring and Troubleshooting

### Check Service Status

```bash
docker compose -f docker-compose-15-features.yml -p ids-rabbitmq-15 ps
```

### View Logs

```bash
# All services
docker compose -f docker-compose-15-features.yml -p ids-rabbitmq-15 logs

# Specific service
docker compose -f docker-compose-15-features.yml -p ids-rabbitmq-15 logs ryu-controller-15
```

### RabbitMQ Queue Status

1. Open http://localhost:15672
2. Login with guest/guest
3. Go to "Queues" tab
4. Check 'features' and 'decisions' queues

### Test ML Model Directly

```bash
curl -X POST http://localhost:5000/predict_15 \
  -H "Content-Type: application/json" \
  -d '{"features": [0,1,0,1,1,0,0.025,1500,0,2,1,0,1,3,40.5]}'
```

## Performance Optimization

The 15-feature version offers several advantages:

1. **Reduced Processing Time**: 55% fewer features to extract and process
2. **Lower Memory Usage**: Smaller feature vectors reduce memory footprint
3. **Faster Model Inference**: Simplified model with fewer input dimensions
4. **Better Real-time Performance**: Reduced computational overhead

## Model Training

To train a new 15-feature model:

1. Prepare training data with exactly 15 features in the specified order
2. Train an XGBoost classifier
3. Save the model as `xgb_model_15.joblib`
4. Optionally create a corresponding scaler file `robust_scaler_15.json`

## Troubleshooting

### Common Issues

1. **Mininet can't connect to Ryu controller**
   - Check if ryu-controller-15 is running
   - Verify port 6653 is accessible
   - Check Docker network connectivity

2. **No decisions in dashboard**
   - Verify ML model server is healthy: `curl http://localhost:5000/health`
   - Check if features are being sent to RabbitMQ
   - Monitor ML consumer logs

3. **Feature validation errors**
   - Ensure exactly 15 features are being sent
   - Check feature data types (must be numeric)
   - Verify feature extraction logic in Ryu controller

### Reset System

```bash
# Stop all services
docker compose -f docker-compose-15-features.yml -p ids-rabbitmq-15 down --volumes

# Remove all containers and volumes
docker compose -f docker-compose-15-features.yml -p ids-rabbitmq-15 down --volumes --remove-orphans

# Restart
./start_15_features_system.sh
```

## Support

For issues specific to the 15-feature version:

1. Check the logs of individual services
2. Verify the feature extraction matches the expected 15-feature format
3. Ensure the ML model supports exactly 15 input features
4. Test the system with known good traffic patterns

The 15-feature system maintains full compatibility with the RabbitMQ message format while providing improved performance through feature reduction.
