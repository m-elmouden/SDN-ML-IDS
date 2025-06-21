#!/bin/bash

# RabbitMQ-based IDS System Startup Script - 15 Features Version
# This script starts all services for the 15-feature IDS system

set -e

echo "=============================================="
echo "Starting RabbitMQ-based IDS System (15 Features)"
echo "=============================================="

# Configuration
COMPOSE_FILE="docker-compose-15-features.yml"
PROJECT_NAME="ids-rabbitmq-15"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check if a service is healthy
check_service_health() {
    local service_name="$1"
    local max_attempts="$2"
    local attempt=1
    
    log_info "Checking health of service: $service_name"
    
    while [ $attempt -le $max_attempts ]; do
        if docker compose -f "$COMPOSE_FILE" -p "$PROJECT_NAME" ps "$service_name" | grep -q "healthy\|Up"; then
            log_success "$service_name is healthy"
            return 0
        fi
        
        log_info "Attempt $attempt/$max_attempts: $service_name not ready yet, waiting..."
        sleep 5
        attempt=$((attempt + 1))
    done
    
    log_error "$service_name failed to become healthy after $max_attempts attempts"
    return 1
}

# Function to wait for RabbitMQ and create initial setup
setup_rabbitmq() {
    log_info "Setting up RabbitMQ..."
    
    # Wait for RabbitMQ to be ready
    if check_service_health "rabbitmq" 12; then
        log_success "RabbitMQ is ready"
        
        # Create queues using RabbitMQ management API
        log_info "Creating RabbitMQ queues..."
        
        # Wait a bit more for management API to be fully ready
        sleep 10
        
        # Create features queue
        docker compose -f "$COMPOSE_FILE" -p "$PROJECT_NAME" exec rabbitmq rabbitmqadmin declare queue name=features durable=true || {
            log_warning "Failed to create features queue (may already exist)"
        }
        
        # Create decisions queue
        docker compose -f "$COMPOSE_FILE" -p "$PROJECT_NAME" exec rabbitmq rabbitmqadmin declare queue name=decisions durable=true || {
            log_warning "Failed to create decisions queue (may already exist)"
        }
        
        log_success "RabbitMQ setup completed"
        return 0
    else
        log_error "RabbitMQ failed to start properly"
        return 1
    fi
}

# Function to display service status
show_status() {
    echo ""
    log_info "Service Status:"
    echo "=============================================="
    docker compose -f "$COMPOSE_FILE" -p "$PROJECT_NAME" ps
    echo "=============================================="
}

# Function to show connection information
show_connections() {
    echo ""
    log_info "Connection Information:"
    echo "=============================================="
    echo "RabbitMQ Management UI: http://localhost:15672 (guest/guest)"
    echo "Dashboard (15 Features): http://localhost:8080"
    echo "ML Model API (15 Features): http://localhost:5000"
    echo "Portainer: http://localhost:9000"
    echo ""
    echo "15-Feature Model Endpoints:"
    echo "  - Health: http://localhost:5000/health"
    echo "  - Predict: http://localhost:5000/predict_15"
    echo "  - Info: http://localhost:5000/info"
    echo "=============================================="
}

# Function to clean up previous containers
cleanup_previous() {
    log_info "Cleaning up previous containers..."
    docker compose -f "$COMPOSE_FILE" -p "$PROJECT_NAME" down --remove-orphans --volumes 2>/dev/null || true
    log_success "Cleanup completed"
}

# Main execution starts here
log_info "Starting 15-Feature IDS System deployment..."

# Check if Docker Compose is available
if ! command -v docker &> /dev/null; then
    log_error "Docker is not installed or not in PATH"
    exit 1
fi

if ! docker compose version &> /dev/null; then
    log_error "Docker Compose is not available"
    exit 1
fi

# Check if compose file exists
if [ ! -f "$COMPOSE_FILE" ]; then
    log_error "Docker Compose file '$COMPOSE_FILE' not found"
    exit 1
fi

# Cleanup previous deployment
cleanup_previous

# Start the services
log_info "Starting all services..."
docker compose -f "$COMPOSE_FILE" -p "$PROJECT_NAME" up -d

# Wait for core services
log_info "Waiting for core services to start..."
sleep 5

# Setup RabbitMQ
if ! setup_rabbitmq; then
    log_error "Failed to setup RabbitMQ"
    show_status
    exit 1
fi

# Wait for ML Model to be ready
log_info "Waiting for ML Model (15 Features) to be ready..."
if check_service_health "ml-model-15" 8; then
    log_success "ML Model (15 Features) is ready"
else
    log_warning "ML Model (15 Features) is not responding properly"
fi

# Wait for ML Consumer
log_info "Waiting for ML Consumer (15 Features) to be ready..."
sleep 10
log_success "ML Consumer (15 Features) should be running"

# Wait for Dashboard
log_info "Waiting for Dashboard (15 Features) to be ready..."
sleep 5
log_success "Dashboard (15 Features) should be ready"

# Final status check
show_status

# Show connection information
show_connections

# Instructions for testing
echo ""
log_info "Testing Instructions:"
echo "=============================================="
echo "1. Connect to Mininet container:"
echo "   docker exec -it mininet bash"
echo ""
echo "2. In Mininet container, run the custom topology:"
echo "   cd /root/scripts"
echo "   python3 custom_topo.py"
echo ""
echo "3. In Mininet CLI, test connectivity:"
echo "   pingall"
echo "   h1 ping h2"
echo ""
echo "4. Generate network traffic for testing:"
echo "   h1 wget http://172.18.0.102"
echo "   h2 iperf -s &"
echo "   h1 iperf -c 172.18.0.102 -t 30"
echo ""
echo "5. Monitor the dashboard at: http://localhost:8080"
echo "6. Check RabbitMQ queues at: http://localhost:15672"
echo "=============================================="

log_success "15-Feature IDS System deployment completed!"
log_info "System is ready for testing with 15-feature ML model"

# Keep script running to show logs
log_info "Press Ctrl+C to stop all services and exit"
trap 'echo ""; log_info "Stopping services..."; docker compose -f "$COMPOSE_FILE" -p "$PROJECT_NAME" down; log_success "All services stopped"; exit 0' INT

# Show live logs from key services
log_info "Showing live logs (press Ctrl+C to stop)..."
docker compose -f "$COMPOSE_FILE" -p "$PROJECT_NAME" logs -f ryu-controller-15 ml-consumer-15 dashboard-15
