#!/usr/bin/env python3
"""
ML Consumer for RabbitMQ - 15 Features Version
Consumes features from RabbitMQ, makes predictions using 15-feature XGBoost model, and sends decisions back
Compatible with Python 3.9
"""

import json
import time
import logging
import os
import sys
from typing import List, Dict, Any
import requests
import pika
import numpy as np

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class MLConsumer15RabbitMQ:
    """ML Consumer for processing 15-feature vectors from RabbitMQ"""
    
    def __init__(self):
        # RabbitMQ configuration
        self.rabbitmq_url = os.getenv('RABBITMQ_URL', 'amqp://guest:guest@rabbitmq:5672/')
        self.features_queue = os.getenv('FEATURES_QUEUE', 'features')
        self.decisions_queue = os.getenv('DECISIONS_QUEUE', 'decisions')
        
        # ML Model configuration
        self.ml_model_url = os.getenv('ML_MODEL_URL', 'http://ml-model:5000')
        self.model_endpoint = '/predict_15'  # Use 15-feature endpoint
        
        # Consumer configuration
        self.max_retries = int(os.getenv('MAX_RETRIES', '5'))
        self.retry_delay = int(os.getenv('RETRY_DELAY', '5'))
          # Expected feature names for validation (15 features)
        self.expected_features = [
            'fin_flag_number', 'psh_flag_number', 'UDP', 'syn_flag_number', 'HTTP',
            'ICMP', 'Tot_sum', 'IAT', 'rst_count', 'Weight',
            'rst_flag_number', 'flow_duration', 'TCP', 'Rate', 'ARP'
        ]
        
        # RabbitMQ connection components
        self.connection = None
        self.channel = None
        self.connected = False
        
        logger.info("ML Consumer (15 Features) initialized")

    def connect_rabbitmq(self) -> bool:
        """Establish connection to RabbitMQ with retry logic"""
        for attempt in range(self.max_retries):
            try:
                logger.info(f"Attempting to connect to RabbitMQ (attempt {attempt + 1}/{self.max_retries})...")
                
                # Parse RabbitMQ URL and create connection parameters
                parameters = pika.URLParameters(self.rabbitmq_url)
                parameters.socket_timeout = 10
                parameters.connection_attempts = 3
                parameters.retry_delay = 2
                
                # Create blocking connection
                self.connection = pika.BlockingConnection(parameters)
                self.channel = self.connection.channel()
                
                # Declare queues (idempotent)
                self.channel.queue_declare(queue=self.features_queue, durable=True)
                self.channel.queue_declare(queue=self.decisions_queue, durable=True)
                
                # Set QoS to process one message at a time
                self.channel.basic_qos(prefetch_count=1)
                
                self.connected = True
                logger.info("Successfully connected to RabbitMQ")
                return True
                
            except Exception as e:
                logger.warning(f"RabbitMQ connection attempt {attempt + 1} failed: {e}")
                
                # Clean up failed connection
                if self.connection and not self.connection.is_closed:
                    try:
                        self.connection.close()
                    except:
                        pass
                self.connection = None
                self.channel = None
                
                if attempt < self.max_retries - 1:
                    logger.info(f"Retrying in {self.retry_delay} seconds...")
                    time.sleep(self.retry_delay)
        
        logger.error(f"Failed to connect to RabbitMQ after {self.max_retries} attempts")
        self.connected = False
        return False

    def validate_features(self, features: List[float]) -> bool:
        """Validate that we have exactly 15 features"""
        if not isinstance(features, list):
            logger.error(f"Features must be a list, got {type(features)}")
            return False
            
        if len(features) != 15:
            logger.error(f"Expected 15 features, got {len(features)}")
            return False
            
        # Check if all features are numeric
        for i, feature in enumerate(features):
            if not isinstance(feature, (int, float)):
                logger.error(f"Feature {i} is not numeric: {feature} (type: {type(feature)})")
                return False
                
        return True

    def call_ml_model(self, features: List[float]) -> Dict[str, Any]:
        """Make prediction using the 15-feature ML model"""
        try:
            # Prepare the payload
            payload = {
                'features': features,
                'feature_count': 15
            }
            
            # Make request to ML model
            url = f"{self.ml_model_url}{self.model_endpoint}"
            logger.debug(f"Calling ML model at {url}")
            
            response = requests.post(
                url,
                json=payload,
                headers={'Content-Type': 'application/json'},
                timeout=10
            )
            
            if response.status_code == 200:
                prediction = response.json()
                logger.debug(f"ML model prediction: {prediction}")
                return prediction
            else:
                logger.error(f"ML model returned status {response.status_code}: {response.text}")
                return None
                
        except requests.exceptions.Timeout:
            logger.error("Timeout calling ML model")
            return None
        except requests.exceptions.ConnectionError:
            logger.error("Connection error calling ML model")
            return None
        except Exception as e:
            logger.error(f"Error calling ML model: {e}")
            return None

    def send_decision_to_rabbitmq(self, flow_id: str, prediction: Dict[str, Any]) -> bool:
        """Send decision back to RabbitMQ decisions queue"""
        try:
            # Extract prediction results
            is_attack = prediction.get('is_attack', False)
            attack_type = prediction.get('attack_type', 0)
            confidence = prediction.get('confidence', 0.0)
            model_used = prediction.get('model', 'xgb_model_15')
            
            # Create decision payload
            decision_payload = {
                'flow_id': flow_id,
                'timestamp': time.time(),
                'is_attack': is_attack,
                'attack_type': int(attack_type),
                'confidence': float(confidence),
                'model_used': model_used,
                'feature_count': 15,
                'source': 'ml_consumer_15'
            }
            
            # Send to RabbitMQ decisions queue
            self.channel.basic_publish(
                exchange='',
                routing_key=self.decisions_queue,
                body=json.dumps(decision_payload),
                properties=pika.BasicProperties(
                    delivery_mode=2,  # Make message persistent
                    content_type='application/json',
                    message_id=flow_id
                )
            )
            
            logger.info(f"Decision sent for flow {flow_id}: {'ATTACK' if is_attack else 'BENIGN'} (confidence: {confidence:.2f})")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send decision to RabbitMQ: {e}")
            return False

    def process_feature_message(self, ch, method, properties, body):
        """Process a single feature message from RabbitMQ"""
        try:
            # Parse the message
            message = json.loads(body)
            flow_id = message.get('flow_id', 'unknown')
            features = message.get('features', [])
            feature_count = message.get('feature_count', len(features))
            
            logger.info(f"Processing features for flow {flow_id} (feature_count: {feature_count})")
            
            # Validate features
            if not self.validate_features(features):
                logger.error(f"Invalid features for flow {flow_id}")
                ch.basic_nack(delivery_tag=method.delivery_tag, requeue=False)
                return
            
            # Call ML model for prediction
            prediction = self.call_ml_model(features)
            if prediction is None:
                logger.error(f"Failed to get prediction for flow {flow_id}")
                ch.basic_nack(delivery_tag=method.delivery_tag, requeue=False)
                return
            
            # Send decision back to RabbitMQ
            if self.send_decision_to_rabbitmq(flow_id, prediction):
                logger.debug(f"Successfully processed flow {flow_id}")
                ch.basic_ack(delivery_tag=method.delivery_tag)
            else:
                logger.error(f"Failed to send decision for flow {flow_id}")
                ch.basic_nack(delivery_tag=method.delivery_tag, requeue=True)
                
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in message: {e}")
            ch.basic_nack(delivery_tag=method.delivery_tag, requeue=False)
        except Exception as e:
            logger.error(f"Error processing message: {e}")
            ch.basic_nack(delivery_tag=method.delivery_tag, requeue=True)

    def start_consuming(self):
        """Start consuming messages from RabbitMQ"""
        if not self.connected:
            if not self.connect_rabbitmq():
                logger.error("Cannot start consuming - not connected to RabbitMQ")
                return
        
        try:
            logger.info(f"Starting to consume from queue: {self.features_queue}")
            
            # Set up consumer
            self.channel.basic_consume(
                queue=self.features_queue,
                on_message_callback=self.process_feature_message
            )
            
            logger.info("ML Consumer (15 Features) is waiting for messages. To exit press CTRL+C")
            
            # Start consuming
            self.channel.start_consuming()
            
        except KeyboardInterrupt:
            logger.info("Received keyboard interrupt, stopping consumer...")
            self.channel.stop_consuming()
            
        except Exception as e:
            logger.error(f"Error during consumption: {e}")
            
        finally:
            if self.connection and not self.connection.is_closed:
                self.connection.close()
                logger.info("RabbitMQ connection closed")

    def run(self):
        """Main run method with reconnection logic"""
        while True:
            try:
                self.start_consuming()
            except Exception as e:
                logger.error(f"Consumer error: {e}")
                logger.info(f"Retrying in {self.retry_delay} seconds...")
                time.sleep(self.retry_delay)
                
                # Reset connection state
                self.connected = False
                if self.connection and not self.connection.is_closed:
                    try:
                        self.connection.close()
                    except:
                        pass


def main():
    """Main entry point"""
    logger.info("Starting ML Consumer for 15-Feature RabbitMQ IDS System")
    
    # Wait for dependencies to be ready
    logger.info("Waiting 10 seconds for dependencies to start...")
    time.sleep(10)
    
    # Create and run consumer
    consumer = MLConsumer15RabbitMQ()
    
    try:
        consumer.run()
    except KeyboardInterrupt:
        logger.info("ML Consumer stopped by user")
    except Exception as e:
        logger.error(f"ML Consumer failed: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
