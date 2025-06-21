#!/bin/bash

KAFKA_HOST=${KAFKA_HOST:-localhost}
KAFKA_PORT=${KAFKA_PORT:-9092}
TOPIC_NAME="test-topic"

echo "Testing Kafka connectivity..."

# Check if Kafka is reachable
nc -z $KAFKA_HOST $KAFKA_PORT
if [ $? -ne 0 ]; then
  echo "Kafka is not reachable at $KAFKA_HOST:$KAFKA_PORT"
  exit 1
fi

echo "Kafka port is reachable. Testing producer/consumer functionality..."

# Create a test topic
kafka-topics.sh --create --if-not-exists --bootstrap-server $KAFKA_HOST:$KAFKA_PORT --replication-factor 1 --partitions 1 --topic $TOPIC_NAME 2>/dev/null

# Try to produce a message
echo "test message" | kafka-console-producer.sh --broker-list $KAFKA_HOST:$KAFKA_PORT --topic $TOPIC_NAME 2>/dev/null
if [ $? -ne 0 ]; then
  echo "Failed to produce a test message to Kafka"
  exit 1
fi

echo "Kafka is fully operational"
exit 0
