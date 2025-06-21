#!/usr/bin/env python3
"""
ML Consumer Service for Kafka-based IDS Pipeline

This service:
1. Consumes feature messages from the 'features' Kafka topic
2. Calls the existing ML inference service
3. Produces decision messages to the 'decisions' Kafka topic

Compatible with Python 3.x and integrates with the existing ML model server.
"""

import json
import time
import logging
import requests
import signal
import sys
from threading import Thread, Event
from typing import Dict, List, Optional

try:
    from kafka import KafkaConsumer, KafkaProducer
    KAFKA_AVAILABLE = True
except ImportError:
    KAFKA_AVAILABLE = False
    print("Error: kafka-python not available. Install with: pip install kafka-python")
    sys.exit(1)


class MLConsumerService:
    """
    ML Consumer Service that processes features from Kafka and produces decisions.
    
    Architecture:
    - Consumes from 'features' topic
    - Calls ML model via REST API
    - Produces to 'decisions' topic
    """
    
    def __init__(self, config: Optional[Dict] = None):
        """Initialize the ML consumer service with configuration."""
        
        # Default configuration
        self.config = {
            'kafka_bootstrap_servers': ['kafka:9092'],
            'features_topic': 'features',
            'decisions_topic': 'decisions',
            'consumer_group_id': 'ml-consumer-group',
            'ml_api_url': 'http://ml-model:5000/predict',
            'ml_health_url': 'http://ml-model:5000/health',
            'log_level': 'INFO',
            'max_retries': 3,
            'retry_delay': 1.0,
            'consumer_timeout_ms': 10000,
            'producer_retries': 3
        }
        
        # Update with provided config
        if config:
            self.config.update(config)
        
        # Initialize logging
        self._setup_logging()
        
        # Initialize state
        self.running = Event()
        self.consumer = None
        self.producer = None
        self.ml_available = False
        
        # Statistics
        self.stats = {
            'messages_processed': 0,
            'ml_predictions_success': 0,
            'ml_predictions_failed': 0,
            'decisions_sent': 0,
            'decisions_failed': 0,
            'start_time': time.time()
        }
        
        self.logger.info("ML Consumer Service initialized")

    def _setup_logging(self):
        """Setup logging configuration."""
        logging.basicConfig(
            level=getattr(logging, self.config['log_level']),
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger('MLConsumerService')

    def _init_kafka_consumer(self):
        """Initialize Kafka consumer for features topic."""
        try:
            self.consumer = KafkaConsumer(
                self.config['features_topic'],
                bootstrap_servers=self.config['kafka_bootstrap_servers'],
                group_id=self.config['consumer_group_id'],
                value_deserializer=lambda x: json.loads(x.decode('utf-8')),
                key_deserializer=lambda x: x.decode('utf-8') if x else None,
                auto_offset_reset='latest',  # Start from latest messages
                enable_auto_commit=True,
                auto_commit_interval_ms=1000,
                consumer_timeout_ms=self.config['consumer_timeout_ms'],
                fetch_max_wait_ms=1000,
                max_poll_records=10  # Process in small batches
            )
            self.logger.info(f"Kafka consumer initialized for topic: {self.config['features_topic']}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to initialize Kafka consumer: {e}")
            return False

    def _init_kafka_producer(self):
        """Initialize Kafka producer for decisions topic."""
        try:
            self.producer = KafkaProducer(
                bootstrap_servers=self.config['kafka_bootstrap_servers'],
                value_serializer=lambda x: json.dumps(x).encode('utf-8'),
                key_serializer=lambda x: x.encode('utf-8') if x else None,
                # Reliability settings
                acks='all',  # Wait for all replicas
                retries=self.config['producer_retries'],
                max_in_flight_requests_per_connection=1,
                # Performance settings
                batch_size=16384,
                linger_ms=10,
                buffer_memory=33554432,
                # Timeout settings
                request_timeout_ms=30000
            )
            self.logger.info("Kafka producer initialized for decisions")
            return True
        except Exception as e:
            self.logger.error(f"Failed to initialize Kafka producer: {e}")
            return False

    def _check_ml_service_health(self):
        """Check if ML service is available."""
        try:
            response = requests.get(
                self.config['ml_health_url'], 
                timeout=5.0
            )
            if response.status_code == 200:
                health_data = response.json()
                self.logger.info(f"ML service healthy - Model: {health_data.get('model_type', 'unknown')}")
                return True
            else:
                self.logger.warning(f"ML service health check failed with status: {response.status_code}")
                return False
        except Exception as e:
            self.logger.warning(f"ML service health check failed: {e}")
            return False

    def _call_ml_service(self, features: List[float]) -> Optional[Dict]:
        """
        Call the ML service with features and return prediction.
        
        Args:
            features: List of 33 feature values
            
        Returns:
            Dictionary with prediction results or None if failed
        """
        payload = {'features': features}
        
        for attempt in range(self.config['max_retries']):
            try:
                response = requests.post(
                    self.config['ml_api_url'],
                    json=payload,
                    timeout=5.0
                )
                
                if response.status_code == 200:
                    result = response.json()
                    self.stats['ml_predictions_success'] += 1
                    return result
                else:
                    self.logger.warning(f"ML service returned status {response.status_code}")
                    
            except Exception as e:
                self.logger.warning(f"ML service call attempt {attempt + 1} failed: {e}")
                
            if attempt < self.config['max_retries'] - 1:
                time.sleep(self.config['retry_delay'])
        
        self.stats['ml_predictions_failed'] += 1
        self.logger.error("All ML service call attempts failed")
        return None

    def _process_feature_message(self, message):
        """
        Process a single feature message from Kafka.
        
        Args:
            message: Kafka message containing feature data
        """
        try:
            # Extract message data
            feature_data = message.value
            flow_id = feature_data.get('flow_id', '')
            features = feature_data.get('features', [])
            timestamp = feature_data.get('timestamp', time.time())
            
            self.logger.debug(f"Processing features for flow: {flow_id}")
            
            # Validate features
            if not features or len(features) != 33:
                self.logger.error(f"Invalid features for flow {flow_id}: expected 33, got {len(features)}")
                return
            
            # Call ML service
            ml_result = self._call_ml_service(features)
            
            if ml_result is None:
                self.logger.error(f"Failed to get ML prediction for flow {flow_id}")
                return
            
            # Extract ML results
            is_attack = ml_result.get('is_attack', False)
            attack_type = ml_result.get('attack_type', 0)
            confidence = ml_result.get('confidence', 0.0)
            
            self.logger.info(f"Flow {flow_id}: {'ATTACK' if is_attack else 'BENIGN'} "
                           f"(type: {attack_type}, confidence: {confidence:.3f})")
            
            # Create decision message
            decision = {
                'flow_id': flow_id,
                'timestamp': time.time(),
                'original_timestamp': timestamp,
                'is_attack': is_attack,
                'attack_type': attack_type,
                'confidence': confidence,
                'features_processed': len(features),
                'ml_model_info': {
                    'model_type': ml_result.get('model_type', 'unknown'),
                    'feature_names': ml_result.get('feature_names', [])
                },
                'processing_metadata': {
                    'processor': 'ml_consumer_service',
                    'version': '1.0',
                    'processing_time': time.time() - timestamp
                }
            }
            
            # Send decision to Kafka
            self._send_decision(decision)
            
            self.stats['messages_processed'] += 1
            
        except Exception as e:
            self.logger.error(f"Error processing feature message: {e}")

    def _send_decision(self, decision: Dict):
        """
        Send decision to Kafka decisions topic.
        
        Args:
            decision: Decision dictionary to send
        """
        try:
            flow_id = decision.get('flow_id', '')
            
            # Send to Kafka with flow_id as key
            future = self.producer.send(
                self.config['decisions_topic'],
                key=flow_id,
                value=decision
            )
            
            # Non-blocking poll to trigger delivery
            self.producer.poll(0)
            
            self.stats['decisions_sent'] += 1
            self.logger.debug(f"Decision sent to Kafka for flow: {flow_id}")
            
        except Exception as e:
            self.stats['decisions_failed'] += 1
            self.logger.error(f"Failed to send decision to Kafka: {e}")

    def _consumer_loop(self):
        """Main consumer loop that processes messages."""
        self.logger.info("Starting consumer loop")
        
        while self.running.is_set():
            try:
                # Poll for messages
                message_batch = self.consumer.poll(timeout_ms=1000)
                
                if not message_batch:
                    continue
                
                # Process each message in the batch
                for topic_partition, messages in message_batch.items():
                    for message in messages:
                        if not self.running.is_set():
                            break
                        self._process_feature_message(message)
                
                # Commit offsets after processing batch
                self.consumer.commit()
                
            except Exception as e:
                self.logger.error(f"Error in consumer loop: {e}")
                time.sleep(1)  # Brief pause before retrying
        
        self.logger.info("Consumer loop stopped")

    def _health_check_loop(self):
        """Background thread to monitor ML service health."""
        self.logger.info("Starting health check loop")
        
        while self.running.is_set():
            try:
                self.ml_available = self._check_ml_service_health()
                time.sleep(30)  # Check every 30 seconds
            except Exception as e:
                self.logger.error(f"Error in health check loop: {e}")
                time.sleep(5)
        
        self.logger.info("Health check loop stopped")

    def _stats_loop(self):
        """Background thread to log statistics."""
        while self.running.is_set():
            try:
                time.sleep(60)  # Log stats every minute
                if self.running.is_set():
                    self._log_statistics()
            except Exception as e:
                self.logger.error(f"Error in stats loop: {e}")

    def _log_statistics(self):
        """Log current processing statistics."""
        uptime = time.time() - self.stats['start_time']
        self.logger.info(
            f"Stats - Uptime: {uptime:.1f}s, "
            f"Processed: {self.stats['messages_processed']}, "
            f"ML Success: {self.stats['ml_predictions_success']}, "
            f"ML Failed: {self.stats['ml_predictions_failed']}, "
            f"Decisions Sent: {self.stats['decisions_sent']}, "
            f"Decisions Failed: {self.stats['decisions_failed']}"
        )

    def start(self):
        """Start the ML consumer service."""
        self.logger.info("Starting ML Consumer Service...")
        
        # Initialize components
        if not self._init_kafka_consumer():
            self.logger.error("Failed to initialize Kafka consumer")
            return False
        
        if not self._init_kafka_producer():
            self.logger.error("Failed to initialize Kafka producer")
            return False
        
        # Check ML service
        self.ml_available = self._check_ml_service_health()
        if not self.ml_available:
            self.logger.warning("ML service not available at startup - will retry")
        
        # Set running flag
        self.running.set()
        
        # Start background threads
        health_thread = Thread(target=self._health_check_loop, daemon=True)
        health_thread.start()
        
        stats_thread = Thread(target=self._stats_loop, daemon=True)
        stats_thread.start()
        
        self.logger.info("ML Consumer Service started successfully")
        
        # Start main consumer loop
        try:
            self._consumer_loop()
        except KeyboardInterrupt:
            self.logger.info("Received interrupt signal")
        finally:
            self.stop()
        
        return True

    def stop(self):
        """Stop the ML consumer service."""
        self.logger.info("Stopping ML Consumer Service...")
        
        # Clear running flag
        self.running.clear()
        
        # Close Kafka connections
        if self.consumer:
            try:
                self.consumer.close()
                self.logger.info("Kafka consumer closed")
            except Exception as e:
                self.logger.error(f"Error closing Kafka consumer: {e}")
        
        if self.producer:
            try:
                self.producer.flush()  # Ensure all messages are sent
                self.producer.close()
                self.logger.info("Kafka producer closed")
            except Exception as e:
                self.logger.error(f"Error closing Kafka producer: {e}")
        
        # Log final statistics
        self._log_statistics()
        self.logger.info("ML Consumer Service stopped")

    def get_status(self) -> Dict:
        """Get current service status."""
        return {
            'running': self.running.is_set(),
            'ml_available': self.ml_available,
            'kafka_consumer_connected': self.consumer is not None,
            'kafka_producer_connected': self.producer is not None,
            'statistics': self.stats.copy()
        }


def signal_handler(signum, frame, service):
    """Handle shutdown signals."""
    print(f"\nReceived signal {signum}, shutting down...")
    service.stop()
    sys.exit(0)


def main():
    """Main entry point for the ML consumer service."""
    
    # Configuration can be overridden via environment variables
    import os
    
    config = {
        'kafka_bootstrap_servers': [os.getenv('KAFKA_BOOTSTRAP_SERVERS', 'kafka:9092')],
        'features_topic': os.getenv('FEATURES_TOPIC', 'features'),
        'decisions_topic': os.getenv('DECISIONS_TOPIC', 'decisions'),
        'consumer_group_id': os.getenv('CONSUMER_GROUP_ID', 'ml-consumer-group'),
        'ml_api_url': os.getenv('ML_API_URL', 'http://ml-model:5000/predict'),
        'ml_health_url': os.getenv('ML_HEALTH_URL', 'http://ml-model:5000/health'),
        'log_level': os.getenv('LOG_LEVEL', 'INFO')
    }
    
    # Create and start service
    service = MLConsumerService(config)
    
    # Setup signal handlers
    signal.signal(signal.SIGINT, lambda s, f: signal_handler(s, f, service))
    signal.signal(signal.SIGTERM, lambda s, f: signal_handler(s, f, service))
    
    # Start service
    success = service.start()
    
    if not success:
        print("Failed to start ML Consumer Service")
        sys.exit(1)


if __name__ == '__main__':
    main()
