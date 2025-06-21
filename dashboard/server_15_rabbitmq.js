const WebSocket = require('ws');
const amqp = require('amqplib');
const http = require('http');
const fs = require('fs');
const path = require('path');

// Configuration
const PORT = process.env.PORT || 8080;
const RABBITMQ_URL = process.env.RABBITMQ_URL || 'amqp://guest:guest@rabbitmq:5672/';
const DECISIONS_QUEUE = process.env.DECISIONS_QUEUE || 'decisions';

console.log('Starting Enhanced Dashboard Server (15 Features) with RabbitMQ integration...');

// Create HTTP server
const server = http.createServer((req, res) => {
    if (req.url === '/' || req.url === '/index.html') {
        // Serve the dashboard HTML
        const htmlPath = path.join(__dirname, 'index.html');
        fs.readFile(htmlPath, 'utf8', (err, data) => {
            if (err) {
                res.writeHead(404);
                res.end('Dashboard not found');
                return;
            }
            res.writeHead(200, { 'Content-Type': 'text/html' });
            res.end(data);
        });
    } else if (req.url === '/health') {
        // Health check endpoint
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
            status: 'healthy',
            timestamp: Date.now(),
            feature_count: 15,
            service: 'dashboard_15'
        }));
    } else {
        res.writeHead(404);
        res.end('Not found');
    }
});

// Create WebSocket server
const wss = new WebSocket.Server({ 
    server,
    path: '/ws'
});

// Store connected clients
const clients = new Set();

// RabbitMQ connection state
let rabbitConnection = null;
let rabbitChannel = null;
let isConnectedToRabbit = false;

// Connection statistics
const stats = {
    connected_clients: 0,
    messages_sent: 0,
    decisions_received: 0,
    last_decision: null,
    feature_count: 15,
    uptime: Date.now()
};

// WebSocket connection handler
wss.on('connection', (ws, req) => {
    console.log('New WebSocket client connected from', req.socket.remoteAddress);
    clients.add(ws);
    stats.connected_clients = clients.size;
    
    // Send welcome message
    ws.send(JSON.stringify({
        type: 'welcome',
        message: 'Connected to Enhanced IDS Dashboard (15 Features)',
        timestamp: Date.now(),
        feature_count: 15,
        stats: stats
    }));
    
    // Handle client messages
    ws.on('message', (message) => {
        try {
            const data = JSON.parse(message);
            console.log('Received message from client:', data);
            
            // Handle different message types
            if (data.type === 'get_stats') {
                ws.send(JSON.stringify({
                    type: 'stats',
                    data: stats,
                    timestamp: Date.now()
                }));
            }
        } catch (err) {
            console.error('Error parsing client message:', err);
        }
    });
    
    // Handle client disconnect
    ws.on('close', () => {
        console.log('WebSocket client disconnected');
        clients.delete(ws);
        stats.connected_clients = clients.size;
    });
    
    // Handle client errors
    ws.on('error', (err) => {
        console.error('WebSocket client error:', err);
        clients.delete(ws);
        stats.connected_clients = clients.size;
    });
});

// Function to broadcast message to all connected clients
function broadcastToClients(message) {
    const messageStr = JSON.stringify(message);
    let sentCount = 0;
    
    clients.forEach((client) => {
        if (client.readyState === WebSocket.OPEN) {
            try {
                client.send(messageStr);
                sentCount++;
            } catch (err) {
                console.error('Error sending message to client:', err);
                clients.delete(client);
            }
        } else {
            clients.delete(client);
        }
    });
    
    stats.connected_clients = clients.size;
    stats.messages_sent += sentCount;
    
    if (sentCount > 0) {
        console.log(`Broadcasted message to ${sentCount} clients`);
    }
}

// Function to connect to RabbitMQ with retry logic
async function connectToRabbitMQ() {
    const maxRetries = 10;
    const retryDelay = 5000; // 5 seconds
    
    for (let attempt = 1; attempt <= maxRetries; attempt++) {
        try {
            console.log(`Attempting to connect to RabbitMQ (attempt ${attempt}/${maxRetries})...`);
            
            // Create connection
            rabbitConnection = await amqp.connect(RABBITMQ_URL);
            rabbitChannel = await rabbitConnection.createChannel();
            
            // Declare queue
            await rabbitChannel.assertQueue(DECISIONS_QUEUE, { durable: true });
            
            console.log('Successfully connected to RabbitMQ');
            isConnectedToRabbit = true;
            
            // Start consuming messages
            startConsumingDecisions();
            
            // Handle connection errors
            rabbitConnection.on('error', (err) => {
                console.error('RabbitMQ connection error:', err);
                isConnectedToRabbit = false;
            });
            
            rabbitConnection.on('close', () => {
                console.log('RabbitMQ connection closed');
                isConnectedToRabbit = false;
                
                // Attempt to reconnect after delay
                setTimeout(() => {
                    if (!isConnectedToRabbit) {
                        console.log('Attempting to reconnect to RabbitMQ...');
                        connectToRabbitMQ();
                    }
                }, retryDelay);
            });
            
            return; // Success, exit retry loop
            
        } catch (err) {
            console.error(`RabbitMQ connection attempt ${attempt} failed:`, err.message);
            
            if (attempt < maxRetries) {
                console.log(`Retrying in ${retryDelay / 1000} seconds...`);
                await new Promise(resolve => setTimeout(resolve, retryDelay));
            } else {
                console.error('Failed to connect to RabbitMQ after all attempts');
            }
        }
    }
}

// Function to start consuming decisions from RabbitMQ
function startConsumingDecisions() {
    if (!rabbitChannel) {
        console.error('No RabbitMQ channel available');
        return;
    }
    
    console.log(`Starting to consume decisions from queue: ${DECISIONS_QUEUE}`);
    
    rabbitChannel.consume(DECISIONS_QUEUE, (msg) => {
        if (msg !== null) {
            try {
                const decision = JSON.parse(msg.content.toString());
                console.log('Received decision:', decision);
                
                stats.decisions_received++;
                stats.last_decision = decision;
                
                // Prepare message for dashboard clients
                const dashboardMessage = {
                    type: 'decision',
                    timestamp: Date.now(),
                    flow_id: decision.flow_id,
                    decision: decision.is_attack ? 'BLOCK' : 'ALLOW',
                    is_attack: decision.is_attack,
                    attack_type: decision.attack_type || 0,
                    confidence: decision.confidence || 0,
                    model_used: decision.model_used || 'unknown',
                    feature_count: decision.feature_count || 15,
                    source: decision.source || 'ml_consumer'
                };
                
                // Broadcast to all connected clients
                broadcastToClients(dashboardMessage);
                
                // Acknowledge the message
                rabbitChannel.ack(msg);
                
            } catch (err) {
                console.error('Error processing decision message:', err);
                rabbitChannel.nack(msg, false, false); // Don't requeue malformed messages
            }
        }
    }, {
        noAck: false // Manual acknowledgment
    });
}

// Function to send periodic status updates
function sendPeriodicUpdates() {
    const statusMessage = {
        type: 'status',
        timestamp: Date.now(),
        stats: {
            ...stats,
            uptime: Date.now() - stats.uptime,
            rabbitmq_connected: isConnectedToRabbit
        },
        feature_count: 15,
        service: 'dashboard_15'
    };
    
    broadcastToClients(statusMessage);
}

// Start the server
server.listen(PORT, () => {
    console.log(`Enhanced Dashboard Server (15 Features) listening on port ${PORT}`);
    console.log(`WebSocket endpoint: ws://localhost:${PORT}/ws`);
    console.log(`Health check: http://localhost:${PORT}/health`);
});

// Connect to RabbitMQ
setTimeout(() => {
    connectToRabbitMQ();
}, 2000); // Wait 2 seconds before connecting

// Send periodic status updates every 30 seconds
setInterval(sendPeriodicUpdates, 30000);

// Graceful shutdown
process.on('SIGINT', () => {
    console.log('Received SIGINT, shutting down gracefully...');
    
    // Close WebSocket server
    wss.close(() => {
        console.log('WebSocket server closed');
    });
    
    // Close RabbitMQ connection
    if (rabbitConnection) {
        rabbitConnection.close();
    }
    
    // Close HTTP server
    server.close(() => {
        console.log('HTTP server closed');
        process.exit(0);
    });
});

console.log('Enhanced Dashboard Server (15 Features) with RabbitMQ integration started successfully');
