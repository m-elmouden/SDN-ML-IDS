#!/usr/bin/env python3
"""
ML Consumer for RabbitMQ-based IDS System
Python 3.9 compatible

Consumes features from RabbitMQ 'features' queue,
calls ML model API for prediction,
publishes results to RabbitMQ 'decisions' queue.
"""

import os
import json
import time
import logging
import signal
import sys
from typing import Dict, Any, Optional
import pika
import requests
import numpy as np

# Configure logging
logging.basicConfig(
    level=getattr(logging, os.getenv('LOG_LEVEL', 'INFO').upper()),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class MLConsumerRabbitMQ:
    """ML Consumer that processes features from RabbitMQ and publishes decisions"""
    
    def __init__(self):
        # Configuration from environment variables
        self.rabbitmq_url = os.getenv('RABBITMQ_URL', 'amqp://guest:guest@rabbitmq:5672/')
        self.features_queue = os.getenv('FEATURES_QUEUE', 'features')
        self.decisions_queue = os.getenv('DECISIONS_QUEUE', 'decisions')
        self.ml_api_url = os.getenv('ML_API_URL', 'http://ml-model:5000/predict')
        self.ml_health_url = os.getenv('ML_HEALTH_URL', 'http://ml-model:5000/health')
        
        # RabbitMQ connection components
        self.connection: Optional[pika.BlockingConnection] = None
        self.channel: Optional[pika.channel.Channel] = None
        self.running = True
        
        # Statistics
        self.messages_processed = 0
        self.messages_failed = 0
        self.start_time = time.time()
        
        # Setup signal handlers for graceful shutdown
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
        
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals gracefully"""
        logger.info(f"Received signal {signum}, shutting down gracefully...")
        self.running = False
        
    def connect_rabbitmq(self) -> bool:
        """Connect to RabbitMQ with retry logic"""
        max_retries = 10
        retry_delay = 5
        
        for attempt in range(max_retries):
            try:
                logger.info(f"Connecting to RabbitMQ (attempt {attempt + 1}/{max_retries})...")
                
                # Parse URL and create connection parameters
                parameters = pika.URLParameters(self.rabbitmq_url)
                parameters.socket_timeout = 10
                parameters.connection_attempts = 3
                parameters.retry_delay = 2
                
                # Create connection
                self.connection = pika.BlockingConnection(parameters)
                self.channel = self.connection.channel()
                
                # Declare queues (idempotent)
                self.channel.queue_declare(queue=self.features_queue, durable=True)
                self.channel.queue_declare(queue=self.decisions_queue, durable=True)
                
                # Set QoS to process one message at a time
                self.channel.basic_qos(prefetch_count=1)
                
                logger.info("Successfully connected to RabbitMQ")
                return True
                
            except Exception as e:
                logger.warning(f"RabbitMQ connection attempt {attempt + 1} failed: {e}")
                
                if self.connection and not self.connection.is_closed:
                    try:
                        self.connection.close()
                    except:
                        pass
                self.connection = None
                self.channel = None
                
                if attempt < max_retries - 1:
                    logger.info(f"Retrying in {retry_delay} seconds...")
                    time.sleep(retry_delay)
                    retry_delay = min(retry_delay * 2, 30)  # Exponential backoff
                    
        logger.error(f"Failed to connect to RabbitMQ after {max_retries} attempts")
        return False
    
    def wait_for_ml_model(self) -> bool:
        """Wait for ML model to be available"""
        max_retries = 20
        retry_delay = 5
        
        logger.info("Waiting for ML model to be available...")
        
        for attempt in range(max_retries):
            try:
                response = requests.get(self.ml_health_url, timeout=5)
                if response.status_code == 200:
                    logger.info("ML model is available")
                    return True
            except Exception as e:
                logger.debug(f"ML model health check failed (attempt {attempt + 1}): {e}")
                
            if attempt < max_retries - 1:
                logger.info(f"ML model not ready, retrying in {retry_delay} seconds...")
                time.sleep(retry_delay)
                
        logger.error("ML model is not available after waiting")
        return False
    
    def predict_with_ml_model(self, features: list) -> Dict[str, Any]:
        """Call ML model API for prediction"""
        try:
            # Prepare the request payload
            payload = {
                'features': features,  # Model expects list of feature vectors
                'feature_names': [
                    'flow_duration', 'Protocol_Type', 'Duration', 'Rate', 'Drate',
                    'fin_flag_number', 'syn_flag_number', 'rst_flag_number', 'psh_flag_number',
                    'ack_flag_number', 'ece_flag_number', 'cwr_flag_number', 'ack_count',
                    'syn_count', 'fin_count', 'urg_count', 'HTTP', 'HTTPS', 'DNS',
                    'Telnet', 'SMTP', 'SSH', 'IRC', 'TCP', 'UDP', 'DHCP', 'ARP',
                    'ICMP', 'IPv', 'LLC', 'Tot_sum', 'IAT', 'Number'
                ]
            }
            
            # Make prediction request
            logger.info("message: to be sent",payload)
            response = requests.post(
                self.ml_api_url,
                json=payload,
                headers={'Content-Type': 'application/json'},
                timeout=10
            )
            
            if response.status_code == 200:
                result = response.json()
                return {
                    'is_attack': bool(result.get('predictions', [0])[0]),
                    'confidence': float(result.get('probabilities', [[0.5, 0.5]])[0][1]),
                    'attack_type': int(result.get('predictions', [0])[0]),
                    'model_status': 'success'
                }
            else:
                logger.error(f"ML model API returned status {response.status_code}: {response.text}")
                return {
                    'is_attack': False,
                    'confidence': 0.0,
                    'attack_type': 0,
                    'model_status': 'api_error'
                }
                
        except requests.exceptions.Timeout:
            logger.error("ML model API request timed out")
            return {
                'is_attack': False,
                'confidence': 0.0,
                'attack_type': 0,
                'model_status': 'timeout'
            }
        except Exception as e:
            logger.error(f"Error calling ML model API: {e}")
            return {
                'is_attack': False,
                'confidence': 0.0,
                'attack_type': 0,
                'model_status': 'error'
            }
    
    def publish_decision(self, flow_id: str, prediction: Dict[str, Any], 
                        original_timestamp: float) -> bool:
        """Publish prediction result to decisions queue"""
        try:
            decision_payload = {
                'flow_id': flow_id,
                'timestamp': time.time(),
                'original_timestamp': original_timestamp,
                'is_attack': prediction['is_attack'],
                'attack_type': prediction['attack_type'],
                'confidence': prediction['confidence'],
                'model_status': prediction['model_status'],
                'processing_time': time.time() - original_timestamp,
                'source': 'ml_consumer_rabbitmq'
            }
            
            # Publish to decisions queue
            self.channel.basic_publish(
                exchange='',
                routing_key=self.decisions_queue,
                body=json.dumps(decision_payload),
                properties=pika.BasicProperties(
                    delivery_mode=2,  # Make message persistent
                    content_type='application/json',
                    message_id=flow_id,
                    timestamp=int(time.time())
                )
            )
            
            logger.debug(f"Decision published for flow {flow_id}: "
                        f"{'ATTACK' if prediction['is_attack'] else 'BENIGN'} "
                        f"(confidence: {prediction['confidence']:.2f})")
            return True
            
        except Exception as e:
            logger.error(f"Failed to publish decision for flow {flow_id}: {e}")
            return False
    
    def process_message(self, ch, method, properties, body):
        """Process a features message from RabbitMQ"""
        try:
            # Parse the message
            message = json.loads(body.decode('utf-8'))
            logger.debug(f"Received message: {message}")
            
            flow_id = message.get('flow_id', 'unknown')
            features = message.get('features', [])
            original_timestamp = message.get('timestamp', time.time())
            
            logger.debug(f"Processing features for flow {flow_id}")
            
            # Validate features
            if not features or len(features) != 33:
                logger.error(f"Invalid features for flow {flow_id}: expected 33 features, got {len(features)}")
                ch.basic_nack(delivery_tag=method.delivery_tag, requeue=False)
                self.messages_failed += 1
                return
            
            # Convert to numpy array and handle any NaN values
            features_array = np.array(features, dtype=np.float32)
            features_array = np.nan_to_num(features_array, nan=0.0, posinf=0.0, neginf=0.0)
            
            # Get prediction from ML model
            prediction = self.predict_with_ml_model(features_array.tolist())
            
            # Publish decision
            if self.publish_decision(flow_id, prediction, original_timestamp):
                ch.basic_ack(delivery_tag=method.delivery_tag)
                self.messages_processed += 1
                
                if self.messages_processed % 100 == 0:
                    runtime = time.time() - self.start_time
                    rate = self.messages_processed / runtime if runtime > 0 else 0
                    logger.info(f"Processed {self.messages_processed} messages "
                              f"({rate:.2f} msg/sec, {self.messages_failed} failed)")
            else:
                ch.basic_nack(delivery_tag=method.delivery_tag, requeue=True)
                self.messages_failed += 1
                
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse message JSON: {e}")
            ch.basic_nack(delivery_tag=method.delivery_tag, requeue=False)
            self.messages_failed += 1
        except Exception as e:
            logger.error(f"Error processing message: {e}")
            ch.basic_nack(delivery_tag=method.delivery_tag, requeue=True)
            self.messages_failed += 1
    
    def start_consuming(self):
        """Start consuming messages from the features queue"""
        if not self.channel:
            logger.error("No RabbitMQ channel available")
            return
            
        try:
            # Set up consumer
            self.channel.basic_consume(
                queue=self.features_queue,
                on_message_callback=self.process_message
            )
            
            logger.info(f"Started consuming from queue '{self.features_queue}'. Press Ctrl+C to stop.")
            
            # Start consuming with timeout to allow graceful shutdown
            while self.running:
                try:
                    self.connection.process_data_events(time_limit=1)
                except pika.exceptions.AMQPConnectionError:
                    logger.error("Lost connection to RabbitMQ, attempting to reconnect...")
                    if not self.connect_rabbitmq():
                        break
                    # Restart consuming after reconnection
                    self.channel.basic_consume(
                        queue=self.features_queue,
                        on_message_callback=self.process_message
                    )
                    
        except KeyboardInterrupt:
            logger.info("Received keyboard interrupt, shutting down...")
        except Exception as e:
            logger.error(f"Error during consumption: {e}")
        finally:
            self.stop_consuming()
    
    def stop_consuming(self):
        """Stop consuming and close connections"""
        try:
            if self.channel and not self.channel.is_closed:
                self.channel.stop_consuming()
                
            if self.connection and not self.connection.is_closed:
                self.connection.close()
                
            runtime = time.time() - self.start_time
            rate = self.messages_processed / runtime if runtime > 0 else 0
            logger.info(f"Consumer stopped. Processed {self.messages_processed} messages "
                       f"in {runtime:.2f} seconds ({rate:.2f} msg/sec, {self.messages_failed} failed)")
                       
        except Exception as e:
            logger.error(f"Error during shutdown: {e}")
    
    def run(self):
        """Main run method"""
        logger.info("Starting ML Consumer for RabbitMQ-based IDS...")
        
        # Wait for ML model to be available
        if not self.wait_for_ml_model():
            logger.error("ML model is not available, exiting")
            sys.exit(1)
        
        # Connect to RabbitMQ
        if not self.connect_rabbitmq():
            logger.error("Failed to connect to RabbitMQ, exiting")
            sys.exit(1)
        
        # Start consuming
        self.start_consuming()

def main():
    """Main entry point"""
    consumer = MLConsumerRabbitMQ()
    consumer.run()

if __name__ == '__main__':
    main()
