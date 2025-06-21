#!/bin/bash

# Cleanup script to remove Kafka-related files and keep only RabbitMQ system

echo "Cleaning up Kafka-related files..."

# Remove Kafka-specific files
rm -f docker-compose.yml
rm -f docker-compose.yml.broken
rm -f enhanced_ids_kafka.py
rm -f kafka-entrypoint.sh
rm -f kafka_check.sh
rm -f kafka_deploy.sh
rm -f README_KAFKA.md

# Remove Kafka scripts
rm -f create_kafka_topics.sh
rm -f fix_kafka_connectivity.ps1
rm -f fix_kafka_connectivity.sh
rm -f fix_kafka_startup.ps1
rm -f fix_kafka_startup.sh
rm -f start_kafka_ids.ps1

# Remove other Kafka-related directories
rm -rf kafka/
rm -rf scripts/

# Remove old logs and troubleshooting files that were Kafka-specific
rm -f network_logs.txt
rm -f ryu_logs.txt

# Keep only RabbitMQ-related files
echo "Remaining files (RabbitMQ system only):"
ls -la

echo "Cleanup completed. Only RabbitMQ-based system files remain."
