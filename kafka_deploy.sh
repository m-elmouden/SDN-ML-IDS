#!/bin/bash

# Enhanced IDS Kafka Deployment Script
# This script provides easy commands to deploy and test the Kafka-enabled IDS system

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
COMPOSE_FILE="docker-compose.yml"
KAFKA_CONTAINER="kafka"
TOPICS_SCRIPT="scripts/create_kafka_topics.sh"

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check if Docker is running
check_docker() {
    if ! docker info >/dev/null 2>&1; then
        print_error "Docker is not running. Please start Docker and try again."
        exit 1
    fi
    print_success "Docker is running"
}

# Function to check if docker-compose is available
check_docker_compose() {
    if ! command -v docker compose >/dev/null 2>&1; then
        print_error "docker compose is not installed. Please install it and try again."
        exit 1
    fi
    print_success "docker compose is available"
}

# Function to wait for service to be healthy
wait_for_service() {
    local service_name=$1
    local max_attempts=30
    local attempt=1
    
    print_status "Waiting for $service_name to be healthy..."
    
    while [ $attempt -le $max_attempts ]; do
        if docker-compose ps $service_name | grep -q "healthy\|Up"; then
            print_success "$service_name is ready"
            return 0
        fi
        
        echo -n "."
        sleep 5
        attempt=$((attempt + 1))
    done
    
    print_error "$service_name failed to become healthy within $((max_attempts * 5)) seconds"
    return 1
}

# Function to create Kafka topics
create_topics() {
    print_status "Creating Kafka topics..."
    
    if [ -f "$TOPICS_SCRIPT" ]; then
        chmod +x "$TOPICS_SCRIPT"
        ./"$TOPICS_SCRIPT"
    else
        print_warning "Topic creation script not found. Creating topics manually..."
        
        # Create features topic
        docker exec $KAFKA_CONTAINER kafka-topics.sh \
            --bootstrap-server kafka:9092 \
            --create \
            --topic features \
            --partitions 3 \
            --replication-factor 1 \
            --if-not-exists
        
        # Create decisions topic
        docker exec $KAFKA_CONTAINER kafka-topics.sh \
            --bootstrap-server kafka:9092 \
            --create \
            --topic decisions \
            --partitions 1 \
            --replication-factor 1 \
            --if-not-exists
        
        print_success "Topics created manually"
    fi
}

# Function to show service status
show_status() {
    print_status "Service Status:"
    echo ""
    docker-compose ps
    echo ""
    
    print_status "Kafka Topics:"
    if docker exec $KAFKA_CONTAINER kafka-topics.sh --bootstrap-server kafka:9092 --list 2>/dev/null; then
        echo ""
    else
        print_warning "Cannot connect to Kafka"
    fi
    
    print_status "Access URLs:"
    echo "  Dashboard:    http://localhost:8080"
    echo "  Kafka UI:     http://localhost:8081"
    echo "  ML Model API: http://localhost:5000"
    echo "  Portainer:    http://localhost:9000"
    echo ""
}

# Function to show logs
show_logs() {
    local service=$1
    if [ -z "$service" ]; then
        print_status "Available services for logs:"
        docker-compose config --services
        echo ""
        print_status "Usage: $0 logs <service_name>"
        return
    fi
    
    print_status "Showing logs for $service (press Ctrl+C to stop):"
    docker-compose logs -f "$service"
}

# Function to test the system
test_system() {
    print_status "Testing Kafka integration..."
    
    # Test 1: Check if all services are running
    print_status "Test 1: Checking service health..."
    if ! docker-compose ps | grep -q "Up.*healthy"; then
        print_warning "Some services are not healthy. Run 'status' command to check."
    else
        print_success "All services appear to be running"
    fi
    
    # Test 2: Check Kafka topics
    print_status "Test 2: Checking Kafka topics..."
    if docker exec $KAFKA_CONTAINER kafka-topics.sh --bootstrap-server kafka:9092 --list | grep -q "features\|decisions"; then
        print_success "Kafka topics exist"
    else
        print_error "Kafka topics not found. Run 'create-topics' command."
        return 1
    fi
    
    # Test 3: Check ML model API
    print_status "Test 3: Checking ML model API..."
    if curl -s http://localhost:5000/health >/dev/null 2>&1; then
        print_success "ML model API is responding"
    else
        print_warning "ML model API is not responding on localhost:5000"
    fi
    
    # Test 4: Check dashboard
    print_status "Test 4: Checking dashboard..."
    if curl -s http://localhost:8080 >/dev/null 2>&1; then
        print_success "Dashboard is accessible"
    else
        print_warning "Dashboard is not responding on localhost:8080"
    fi
    
    print_success "System test completed"
}

# Function to monitor Kafka messages
monitor_kafka() {
    local topic=$1
    
    if [ -z "$topic" ]; then
        print_status "Available topics:"
        docker exec $KAFKA_CONTAINER kafka-topics.sh --bootstrap-server kafka:9092 --list 2>/dev/null || print_error "Cannot connect to Kafka"
        echo ""
        print_status "Usage: $0 monitor <topic_name>"
        print_status "Example: $0 monitor features"
        return
    fi
    
    print_status "Monitoring messages on topic '$topic' (press Ctrl+C to stop):"
    docker exec $KAFKA_CONTAINER kafka-console-consumer.sh \
        --bootstrap-server kafka:9092 \
        --topic "$topic" \
        --from-beginning \
        --property print.key=true \
        --property key.separator=" : "
}

# Function to generate test traffic
generate_traffic() {
    print_status "Generating test network traffic..."
    
    if ! docker-compose ps mininet | grep -q "Up"; then
        print_error "Mininet container is not running"
        return 1
    fi
    
    print_status "Starting test traffic generation in mininet..."
    docker exec mininet bash -c "
        echo 'Generating test traffic patterns...'
        # Simple ping test
        ping -c 10 8.8.8.8 &
        
        # HTTP requests (if curl is available)
        command -v curl >/dev/null 2>&1 && curl -s http://httpbin.org/get >/dev/null &
        
        # Multiple connections
        for i in {1..5}; do
            nc -z google.com 80 2>/dev/null &
        done
        
        wait
        echo 'Test traffic generation completed'
    "
}

# Function to clean up everything
cleanup() {
    print_status "Cleaning up Enhanced IDS system..."
    
    print_status "Stopping all services..."
    docker-compose down
    
    print_status "Removing volumes (optional)..."
    read -p "Do you want to remove all data volumes? [y/N]: " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        docker-compose down -v
        print_success "Volumes removed"
    fi
    
    print_success "Cleanup completed"
}

# Function to deploy the system
deploy() {
    print_status "Deploying Enhanced IDS with Kafka integration..."
    
    # Check prerequisites
    check_docker
    check_docker_compose
    
    # Start services
    print_status "Starting services..."
    docker compose up -d
    
    # Wait for core services
    print_status "Waiting for core services to start..."
    sleep 10
    
    wait_for_service "zookeeper"
    wait_for_service "kafka"
    
    # Create topics
    create_topics
    
    # Wait for application services
    wait_for_service "ml-model"
    
    print_success "Deployment completed successfully!"
    echo ""
    show_status
}

# Function to show usage
usage() {
    echo "Enhanced IDS Kafka Deployment Script"
    echo ""
    echo "Usage: $0 <command> [options]"
    echo ""
    echo "Commands:"
    echo "  deploy          Deploy the complete system"
    echo "  status          Show status of all services"
    echo "  create-topics   Create required Kafka topics"
    echo "  test            Run system tests"
    echo "  logs <service>  Show logs for a specific service"
    echo "  monitor <topic> Monitor Kafka messages on a topic"
    echo "  traffic         Generate test network traffic"
    echo "  cleanup         Stop and clean up all services"
    echo "  help            Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 deploy                    # Deploy the complete system"
    echo "  $0 status                    # Check service status"
    echo "  $0 logs ryu-custom          # Show Ryu controller logs"
    echo "  $0 monitor features         # Monitor feature messages"
    echo "  $0 test                     # Run system tests"
    echo ""
}

# Main script logic
case "${1:-help}" in
    deploy)
        deploy
        ;;
    status)
        show_status
        ;;
    create-topics)
        create_topics
        ;;
    test)
        test_system
        ;;
    logs)
        show_logs "$2"
        ;;
    monitor)
        monitor_kafka "$2"
        ;;
    traffic)
        generate_traffic
        ;;
    cleanup)
        cleanup
        ;;
    help|--help|-h)
        usage
        ;;
    *)
        print_error "Unknown command: $1"
        echo ""
        usage
        exit 1
        ;;
esac
