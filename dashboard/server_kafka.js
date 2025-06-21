const http = require('http');
const fs = require('fs');
const path = require('path');
const WebSocket = require('ws');

// Add Kafka client for consuming decisions
let kafkaConsumer = null;
try {
  const { KafkaConsumer } = require('node-rdkafka');
  kafkaConsumer = KafkaConsumer;
} catch (error) {
  console.log('Kafka client not available. Install with: npm install node-rdkafka');
  console.log('Falling back to WebSocket-only mode');
}

// Dashboard server with Kafka integration
class DashboardServer {
  constructor() {
    this.clients = new Set();
    this.kafkaConsumer = null;
    this.kafkaConnected = false;
    
    // Configuration
    this.config = {
      kafkaBootstrapServers: process.env.KAFKA_BOOTSTRAP_SERVERS || 'kafka:9092',
      decisionsTopicName: process.env.DECISIONS_TOPIC || 'decisions',
      consumerGroupId: process.env.CONSUMER_GROUP_ID || 'dashboard-consumer-group',
      port: process.env.PORT || 8080,
      host: process.env.HOST_IP || '0.0.0.0'
    };
    
    this.initHttpServer();
    this.initWebSocketServer();
    this.initKafkaConsumer();
  }

  initHttpServer() {
    // Create HTTP server
    this.server = http.createServer((req, res) => {
      // Serve static files
      let filePath = path.join(__dirname, req.url === '/' ? 'index.html' : req.url);
      const extname = path.extname(filePath);
      
      // Set content type based on file extension
      let contentType = 'text/html';
      switch (extname) {
        case '.js':
          contentType = 'text/javascript';
          break;
        case '.css':
          contentType = 'text/css';
          break;
        case '.json':
          contentType = 'application/json';
          break;
      }
      
      // Read file and serve it
      fs.readFile(filePath, (err, content) => {
        if (err) {
          if (err.code === 'ENOENT') {
            // Page not found
            res.writeHead(404);
            res.end('404 - File Not Found');
          } else {
            // Server error
            res.writeHead(500);
            res.end(`Server Error: ${err.code}`);
          }
        } else {
          // Success
          res.writeHead(200, { 'Content-Type': contentType });
          res.end(content, 'utf-8');
        }
      });
    });
  }

  initWebSocketServer() {
    // Create WebSocket server
    this.wss = new WebSocket.Server({ server: this.server, path: '/ws' });

    // WebSocket connection handler
    this.wss.on('connection', (ws) => {
      console.log('Client connected to WebSocket');
      this.clients.add(ws);
      
      // Send initial status
      const initialData = {
        timestamp: Date.now(),
        type: 'status',
        message: 'Connected to Enhanced IDS Dashboard',
        kafka_enabled: this.kafkaConnected,
        features: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        packet_count: 0,
        decision: 'ALLOW',
        attack_type: 0,
        confidence: 0,
        flow_id: '',
        flow_duration: 0
      };
      ws.send(JSON.stringify(initialData));
      
      // Handle messages from clients
      ws.on('message', (message) => {
        try {
          // Parse the message to ensure it's valid JSON
          const data = JSON.parse(message.toString());
          
          // Forward the message to all connected clients
          this.broadcastToClients(message.toString());
          console.log('Message forwarded to clients:', data.type || 'unknown type');
        } catch (error) {
          console.error('Error processing message:', error);
        }
      });
      
      // Handle disconnection
      ws.on('close', () => {
        console.log('Client disconnected from WebSocket');
        this.clients.delete(ws);
      });

      // Handle WebSocket errors
      ws.on('error', (error) => {
        console.error('WebSocket error:', error);
        this.clients.delete(ws);
      });
    });
  }

  initKafkaConsumer() {
    if (!kafkaConsumer) {
      console.log('Kafka consumer not available - using WebSocket-only mode');
      return;
    }

    try {
      // Initialize Kafka consumer
      this.kafkaConsumer = new kafkaConsumer({
        'group.id': this.config.consumerGroupId,
        'metadata.broker.list': this.config.kafkaBootstrapServers,
        'auto.offset.reset': 'latest',
        'enable.auto.commit': true
      }, {
        'auto.offset.reset': 'latest'
      });

      // Handle Kafka events
      this.kafkaConsumer.on('ready', () => {
        console.log('Kafka consumer ready');
        this.kafkaConnected = true;
        
        // Subscribe to decisions topic
        this.kafkaConsumer.subscribe([this.config.decisionsTopicName]);
        
        // Start consuming
        this.kafkaConsumer.consume();
        
        // Notify clients about Kafka connection
        this.broadcastToClients(JSON.stringify({
          timestamp: Date.now(),
          type: 'kafka_status',
          message: 'Kafka consumer connected',
          kafka_enabled: true
        }));
      });

      this.kafkaConsumer.on('data', (message) => {
        try {
          // Parse the decision message
          const decision = JSON.parse(message.value.toString());
          
          console.log(`Received decision from Kafka: ${decision.flow_id} - ${decision.is_attack ? 'ATTACK' : 'BENIGN'}`);
          
          // Forward decision to all WebSocket clients
          const dashboardMessage = {
            timestamp: Date.now(),
            type: 'ml_decision',
            source: 'kafka',
            flow_id: decision.flow_id,
            decision: decision.is_attack ? 'BLOCK' : 'ALLOW',
            attack_type: decision.attack_type,
            confidence: decision.confidence,
            processing_time: decision.processing_metadata?.processing_time || 0,
            original_timestamp: decision.original_timestamp,
            features_processed: decision.features_processed || 0
          };
          
          this.broadcastToClients(JSON.stringify(dashboardMessage));
          
        } catch (error) {
          console.error('Error processing Kafka message:', error);
        }
      });

      this.kafkaConsumer.on('error', (error) => {
        console.error('Kafka consumer error:', error);
        this.kafkaConnected = false;
        
        // Notify clients about Kafka disconnection
        this.broadcastToClients(JSON.stringify({
          timestamp: Date.now(),
          type: 'kafka_status',
          message: 'Kafka consumer error',
          kafka_enabled: false,
          error: error.message
        }));
      });

      this.kafkaConsumer.on('disconnected', () => {
        console.log('Kafka consumer disconnected');
        this.kafkaConnected = false;
        
        // Notify clients about Kafka disconnection
        this.broadcastToClients(JSON.stringify({
          timestamp: Date.now(),
          type: 'kafka_status',
          message: 'Kafka consumer disconnected',
          kafka_enabled: false
        }));
      });

      // Connect to Kafka
      this.kafkaConsumer.connect();

    } catch (error) {
      console.error('Failed to initialize Kafka consumer:', error);
      this.kafkaConnected = false;
    }
  }

  broadcastToClients(message) {
    // Send message to all connected WebSocket clients
    this.clients.forEach((client) => {
      if (client.readyState === WebSocket.OPEN) {
        try {
          client.send(message);
        } catch (error) {
          console.error('Error sending message to client:', error);
          this.clients.delete(client);
        }
      } else {
        this.clients.delete(client);
      }
    });
  }

  start() {
    // Start server
    this.server.listen(this.config.port, this.config.host, () => {
      console.log(`Dashboard server running on ${this.config.host}:${this.config.port}`);
      console.log(`WebSocket server available at ws://${this.config.host}:${this.config.port}/ws`);
      
      if (this.kafkaConnected) {
        console.log(`Kafka consumer enabled for topic: ${this.config.decisionsTopicName}`);
      } else {
        console.log('Kafka consumer disabled - using WebSocket-only mode');
      }
    });
  }

  stop() {
    console.log('Stopping dashboard server...');
    
    // Close Kafka consumer
    if (this.kafkaConsumer) {
      this.kafkaConsumer.disconnect();
    }
    
    // Close all WebSocket connections
    this.clients.forEach((client) => {
      client.close();
    });
    
    // Close HTTP server
    this.server.close(() => {
      console.log('Dashboard server stopped');
    });
  }
}

// Create and start dashboard server
const dashboard = new DashboardServer();

// Handle graceful shutdown
process.on('SIGINT', () => {
  console.log('\nReceived SIGINT, shutting down gracefully...');
  dashboard.stop();
  process.exit(0);
});

process.on('SIGTERM', () => {
  console.log('Received SIGTERM, shutting down gracefully...');
  dashboard.stop();
  process.exit(0);
});

// Handle uncaught exceptions
process.on('uncaughtException', (error) => {
  console.error('Uncaught exception:', error);
  dashboard.stop();
  process.exit(1);
});

// Start the server
dashboard.start();
