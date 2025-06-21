#!/bin/bash

# RabbitMQ-based IDS System Startup Script
# This script starts all services in the correct order and waits for dependencies

set -e

echo "=============================================="
echo "Starting RabbitMQ-based IDS System"
echo "=============================================="

# Configuration
COMPOSE_FILE="docker-compose-rabbitmq.yml"
PROJECT_NAME="ids-rabbitmq"

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
    echo ""
}

# Function to show service URLs
show_urls() {
    echo ""
    log_success "System is ready! Access points:"
    echo "=============================================="
    echo "🐰 RabbitMQ Management UI: http://localhost:15672"
    echo "   Username: guest, Password: guest"
    echo ""
    echo "📊 Dashboard: http://localhost:8080"
    echo ""
    echo "🤖 ML Model API: http://localhost:5000"
    echo "   Health: http://localhost:5000/health"
    echo "   Predict: http://localhost:5000/predict"
    echo ""
    echo "🐳 Portainer: http://localhost:9000"
    echo "=============================================="
    echo ""
}

# Function to cleanup previous runs
cleanup() {
    log_info "Cleaning up previous runs..."
    docker compose -f "$COMPOSE_FILE" -p "$PROJECT_NAME" down -v 2>/dev/null || true
    docker system prune -f 2>/dev/null || true
    log_success "Cleanup completed"
}

# Function for graceful shutdown
graceful_shutdown() {
    echo ""
    log_info "Received shutdown signal. Stopping services gracefully..."
    docker compose -f "$COMPOSE_FILE" -p "$PROJECT_NAME" down
    log_success "All services stopped"
    exit 0
}

# Setup signal handlers
trap graceful_shutdown SIGINT SIGTERM

# Main execution
main() {
    # Check if Docker and Docker Compose are available
    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed or not in PATH"
        exit 1
    fi
    
    if ! command -v docker compose &> /dev/null; then
        log_error "Docker Compose is not installed or not in PATH"
        exit 1
    fi
    
    # Check if compose file exists
    if [ ! -f "$COMPOSE_FILE" ]; then
        log_error "Docker Compose file not found: $COMPOSE_FILE"
        exit 1
    fi
    
    # Clean up any previous runs
    cleanup
    
    # Start all services
    log_info "Starting all services..."
    docker compose -f "$COMPOSE_FILE" -p "$PROJECT_NAME" up -d
    
    # Wait for RabbitMQ and set it up
    if ! setup_rabbitmq; then
        log_error "Failed to setup RabbitMQ"
        exit 1
    fi
    
    # Wait for ML model to be ready
    log_info "Waiting for ML model to be ready..."
    if check_service_health "ml-model" 20; then
        log_success "ML model is ready"
    else
        log_warning "ML model may not be fully ready, but continuing..."
    fi
    
    # Show final status
    show_status
    show_urls
    
    # Keep the script running and show logs
    log_info "System started successfully! Press Ctrl+C to stop."
    log_info "Following logs from all services..."
    echo ""
    
    # Follow logs from all services
    docker compose -f "$COMPOSE_FILE" -p "$PROJECT_NAME" logs -f
}

# Run main function
main "$@"
