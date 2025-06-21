#!/bin/bash

# Simple Kafka IDS Startup Script for Linux
# Use this script to start the Enhanced IDS system with proper service ordering

set -e

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo "========================================="
echo "  Enhanced IDS with Kafka - Startup"
echo "========================================="
echo ""

# Function to wait for service
wait_for_service() {
    local service_name=$1
    local max_attempts=30
    local attempt=1
    
    echo -e "${BLUE}[INFO]${NC} Waiting for $service_name to be ready..."
    
    while [ $attempt -le $max_attempts ]; do
        if docker compose ps $service_name | grep -q "healthy\|Up"; then
            echo -e "${GREEN}[SUCCESS]${NC} $service_name is ready"
            return 0
        fi
        
        echo -n "."
        sleep 5
        attempt=$((attempt + 1))
    done
    
    echo -e "\n${YELLOW}[WARNING]${NC} $service_name may not be fully ready"
    return 1
}

# Start all services
echo -e "${BLUE}[INFO]${NC} Starting all services..."
docker compose up -d

# Wait for core infrastructure
echo ""
wait_for_service "zookeeper"
wait_for_service "kafka"

# Create Kafka topics
echo ""
echo -e "${BLUE}[INFO]${NC} Creating Kafka topics..."

echo "Creating 'features' topic..."
docker exec kafka kafka-topics.sh \
    --bootstrap-server kafka:9092 \
    --create \
    --topic features \
    --partitions 3 \
    --replication-factor 1 \
    --if-not-exists

echo "Creating 'decisions' topic..."
docker exec kafka kafka-topics.sh \
    --bootstrap-server kafka:9092 \
    --create \
    --topic decisions \
    --partitions 1 \
    --replication-factor 1 \
    --if-not-exists

# Wait for application services
echo ""
wait_for_service "ml-model"
wait_for_service "dashboard"

# Give Ryu extra time to connect to Kafka
echo ""
echo -e "${BLUE}[INFO]${NC} Waiting for Ryu controller to connect to Kafka..."
sleep 15

# Show status
echo ""
echo -e "${GREEN}[SUCCESS]${NC} Startup completed!"
echo ""
echo "📊 Service Status:"
docker compose ps
echo ""
echo "🔗 Access URLs:"
echo "  Dashboard:    http://localhost:8080"
echo "  Kafka UI:     http://localhost:8081"
echo "  ML Model API: http://localhost:5000"
echo "  Portainer:    http://localhost:9000"
echo ""
echo "📈 Monitor Kafka messages:"
echo "  docker exec kafka kafka-console-consumer.sh --bootstrap-server kafka:9092 --topic features"
echo "  docker exec kafka kafka-console-consumer.sh --bootstrap-server kafka:9092 --topic decisions"
echo ""
echo "📋 Check logs:"
echo "  docker compose logs ryu-custom"
echo "  docker compose logs ml-consumer"
echo ""
echo "🚀 System is ready!"
