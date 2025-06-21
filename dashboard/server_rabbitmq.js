/**
 * Dashboard Server with RabbitMQ Integration
 * Node.js WebSocket server that consumes decisions from RabbitMQ
 * and broadcasts them to connected clients
 */

const WebSocket = require('ws');
const http = require('http');
const fs = require('fs');
const path = require('path');
const amqp = require('amqplib');

// Configuration from environment variables
const config = {
    port: process.env.PORT || 8080,
    rabbitmqUrl: process.env.RABBITMQ_URL || 'amqp://guest:guest@rabbitmq:5672/',
    decisionsQueue: process.env.DECISIONS_QUEUE || 'decisions',
    logLevel: process.env.LOG_LEVEL || 'info'
};

// Logging utility
const log = {
    debug: (msg) => config.logLevel === 'debug' && console.log(`[DEBUG] ${new Date().toISOString()} - ${msg}`),
    info: (msg) => console.log(`[INFO] ${new Date().toISOString()} - ${msg}`),
    warn: (msg) => console.warn(`[WARN] ${new Date().toISOString()} - ${msg}`),
    error: (msg) => console.error(`[ERROR] ${new Date().toISOString()} - ${msg}`)
};

class DashboardServer {
    constructor() {
        this.server = null;
        this.wss = null;
        this.rabbitmqConnection = null;
        this.rabbitmqChannel = null;
        this.connectedClients = new Set();
        this.stats = {
            startTime: Date.now(),
            messagesReceived: 0,
            messagesBroadcast: 0,
            currentConnections: 0
        };
    }

    // Create HTTP server and serve static files
    createHttpServer() {
        this.server = http.createServer((req, res) => {
            let filePath = '.' + req.url;
            if (filePath === './') {
                filePath = './index.html';
            }

            const extname = path.extname(filePath).toLowerCase();
            const mimeTypes = {
                '.html': 'text/html',
                '.js': 'text/javascript',
                '.css': 'text/css',
                '.json': 'application/json',
                '.png': 'image/png',
                '.jpg': 'image/jpg',
                '.gif': 'image/gif',
                '.svg': 'image/svg+xml',
                '.wav': 'audio/wav',
                '.mp4': 'video/mp4',
                '.woff': 'application/font-woff',
                '.ttf': 'application/font-ttf',
                '.eot': 'application/vnd.ms-fontobject',
                '.otf': 'application/font-otf',
                '.wasm': 'application/wasm'
            };

            const contentType = mimeTypes[extname] || 'application/octet-stream';

            fs.readFile(filePath, (error, content) => {
                if (error) {
                    if (error.code === 'ENOENT') {
                        // Serve a simple default page if index.html doesn't exist
                        const defaultPage = `
<!DOCTYPE html>
<html>
<head>
    <title>IDS Dashboard</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f0f0f0; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; }
        .status { padding: 10px; margin: 10px 0; border-radius: 4px; }
        .connected { background: #d4edda; color: #155724; border: 1px solid #c3e6cb; }
        .disconnected { background: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }
        .decisions { margin-top: 20px; }
        .decision { padding: 10px; margin: 5px 0; border-radius: 4px; border-left: 4px solid #007bff; }
        .attack { border-left-color: #dc3545; background: #f8d7da; }
        .benign { border-left-color: #28a745; background: #d4edda; }
        .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 10px; margin: 20px 0; }
        .stat-card { background: #e9ecef; padding: 15px; border-radius: 4px; text-align: center; }
    </style>
</head>
<body>
    <div class="container">
        <h1>IDS Dashboard - RabbitMQ Integration</h1>
        
        <div id="connection-status" class="status disconnected">
            Connecting to WebSocket...
        </div>
        
        <div class="stats">
            <div class="stat-card">
                <h3 id="total-decisions">0</h3>
                <p>Total Decisions</p>
            </div>
            <div class="stat-card">
                <h3 id="attacks-detected">0</h3>
                <p>Attacks Detected</p>
            </div>
            <div class="stat-card">
                <h3 id="benign-flows">0</h3>
                <p>Benign Flows</p>
            </div>
            <div class="stat-card">
                <h3 id="uptime">0s</h3>
                <p>Uptime</p>
            </div>
        </div>
        
        <h2>Recent Decisions</h2>
        <div id="decisions" class="decisions"></div>
    </div>

    <script>
        let ws;
        let stats = { total: 0, attacks: 0, benign: 0, startTime: Date.now() };
        
        function connect() {
            const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
            ws = new WebSocket(protocol + '//' + window.location.host + '/ws');
            
            ws.onopen = function() {
                document.getElementById('connection-status').textContent = 'Connected to Dashboard';
                document.getElementById('connection-status').className = 'status connected';
            };
            
            ws.onmessage = function(event) {
                try {
                    const data = JSON.parse(event.data);
                    handleDecision(data);
                } catch (e) {
                    console.error('Error parsing message:', e);
                }
            };
            
            ws.onclose = function() {
                document.getElementById('connection-status').textContent = 'Disconnected - Reconnecting...';
                document.getElementById('connection-status').className = 'status disconnected';
                setTimeout(connect, 3000);
            };
            
            ws.onerror = function(error) {
                console.error('WebSocket error:', error);
            };
        }
        
        function handleDecision(data) {
            stats.total++;
            if (data.is_attack) {
                stats.attacks++;
            } else {
                stats.benign++;
            }
            
            updateStats();
            addDecisionToUI(data);
        }
        
        function updateStats() {
            document.getElementById('total-decisions').textContent = stats.total;
            document.getElementById('attacks-detected').textContent = stats.attacks;
            document.getElementById('benign-flows').textContent = stats.benign;
            
            const uptime = Math.floor((Date.now() - stats.startTime) / 1000);
            document.getElementById('uptime').textContent = uptime + 's';
        }
        
        function addDecisionToUI(data) {
            const decisionsDiv = document.getElementById('decisions');
            const decisionDiv = document.createElement('div');
            
            const timestamp = new Date(data.timestamp).toLocaleTimeString();
            const decision = data.is_attack ? 'ATTACK' : 'BENIGN';
            const confidence = (data.confidence * 100).toFixed(1);
            
            decisionDiv.className = 'decision ' + (data.is_attack ? 'attack' : 'benign');
            decisionDiv.innerHTML = 
                '<strong>' + decision + '</strong> - ' +
                'Flow: ' + data.flow_id + ' | ' +
                'Confidence: ' + confidence + '% | ' +
                'Time: ' + timestamp + ' | ' +
                'Source: ' + (data.source || 'unknown');
            
            decisionsDiv.insertBefore(decisionDiv, decisionsDiv.firstChild);
            
            // Keep only last 50 decisions
            while (decisionsDiv.children.length > 50) {
                decisionsDiv.removeChild(decisionsDiv.lastChild);
            }
        }
        
        // Update uptime every second
        setInterval(updateStats, 1000);
        
        // Connect when page loads
        connect();
    </script>
</body>
</html>`;
                        res.writeHead(200, { 'Content-Type': 'text/html' });
                        res.end(defaultPage, 'utf-8');
                    } else {
                        res.writeHead(500);
                        res.end(`Server Error: ${error.code}`);
                    }
                } else {
                    res.writeHead(200, { 'Content-Type': contentType });
                    res.end(content, 'utf-8');
                }
            });
        });
    }

    // Create WebSocket server
    createWebSocketServer() {
        this.wss = new WebSocket.Server({ 
            server: this.server,
            path: '/ws'
        });

        this.wss.on('connection', (ws, req) => {
            const clientIp = req.socket.remoteAddress;
            log.info(`New WebSocket connection from ${clientIp}`);
            
            this.connectedClients.add(ws);
            this.stats.currentConnections = this.connectedClients.size;

            // Send welcome message with current stats
            ws.send(JSON.stringify({
                type: 'welcome',
                stats: this.stats,
                timestamp: Date.now()
            }));

            ws.on('close', () => {
                log.debug(`WebSocket connection closed from ${clientIp}`);
                this.connectedClients.delete(ws);
                this.stats.currentConnections = this.connectedClients.size;
            });

            ws.on('error', (error) => {
                log.error(`WebSocket error from ${clientIp}: ${error.message}`);
                this.connectedClients.delete(ws);
                this.stats.currentConnections = this.connectedClients.size;
            });

            // Send ping every 30 seconds to keep connection alive
            const pingInterval = setInterval(() => {
                if (ws.readyState === WebSocket.OPEN) {
                    ws.ping();
                } else {
                    clearInterval(pingInterval);
                }
            }, 30000);
        });
    }

    // Connect to RabbitMQ
    async connectRabbitMQ() {
        const maxRetries = 10;
        let retryDelay = 5000;

        for (let attempt = 1; attempt <= maxRetries; attempt++) {
            try {
                log.info(`Connecting to RabbitMQ (attempt ${attempt}/${maxRetries})...`);
                
                this.rabbitmqConnection = await amqp.connect(config.rabbitmqUrl);
                this.rabbitmqChannel = await this.rabbitmqConnection.createChannel();
                
                // Declare the decisions queue
                await this.rabbitmqChannel.assertQueue(config.decisionsQueue, { durable: true });
                
                log.info('Successfully connected to RabbitMQ');
                return true;
                
            } catch (error) {
                log.warn(`RabbitMQ connection attempt ${attempt} failed: ${error.message}`);
                
                if (this.rabbitmqConnection) {
                    try {
                        await this.rabbitmqConnection.close();
                    } catch (e) {
                        // Ignore close errors
                    }
                    this.rabbitmqConnection = null;
                    this.rabbitmqChannel = null;
                }
                
                if (attempt < maxRetries) {
                    log.info(`Retrying in ${retryDelay / 1000} seconds...`);
                    await new Promise(resolve => setTimeout(resolve, retryDelay));
                    retryDelay = Math.min(retryDelay * 2, 30000); // Exponential backoff, max 30s
                }
            }
        }
        
        log.error(`Failed to connect to RabbitMQ after ${maxRetries} attempts`);
        return false;
    }

    // Start consuming decisions from RabbitMQ
    async startConsumingDecisions() {
        if (!this.rabbitmqChannel) {
            log.error('No RabbitMQ channel available for consuming');
            return;
        }

        try {
            log.info(`Starting to consume decisions from queue '${config.decisionsQueue}'`);
            
            await this.rabbitmqChannel.consume(config.decisionsQueue, (msg) => {
                if (msg) {
                    try {
                        const decision = JSON.parse(msg.content.toString());
                        this.handleDecision(decision);
                        this.rabbitmqChannel.ack(msg);
                        
                    } catch (error) {
                        log.error(`Error processing decision message: ${error.message}`);
                        this.rabbitmqChannel.nack(msg, false, false); // Don't requeue invalid messages
                    }
                }
            }, { noAck: false });
            
            log.info('Started consuming decisions from RabbitMQ');
            
        } catch (error) {
            log.error(`Error starting RabbitMQ consumer: ${error.message}`);
            throw error;
        }
    }

    // Handle decision message from RabbitMQ
    handleDecision(decision) {
        log.debug(`Received decision for flow ${decision.flow_id}: ${decision.is_attack ? 'ATTACK' : 'BENIGN'}`);
        
        this.stats.messagesReceived++;
        
        // Broadcast to all connected WebSocket clients
        const message = JSON.stringify({
            ...decision,
            timestamp: decision.timestamp * 1000 // Convert to milliseconds for JavaScript
        });
        
        let broadcastCount = 0;
        this.connectedClients.forEach(ws => {
            if (ws.readyState === WebSocket.OPEN) {
                try {
                    ws.send(message);
                    broadcastCount++;
                } catch (error) {
                    log.error(`Error sending message to client: ${error.message}`);
                    this.connectedClients.delete(ws);
                }
            } else {
                this.connectedClients.delete(ws);
            }
        });
        
        this.stats.messagesBroadcast += broadcastCount;
        this.stats.currentConnections = this.connectedClients.size;
        
        // Log statistics every 100 messages
        if (this.stats.messagesReceived % 100 === 0) {
            const runtime = (Date.now() - this.stats.startTime) / 1000;
            const rate = this.stats.messagesReceived / runtime;
            log.info(`Processed ${this.stats.messagesReceived} decisions ` +
                    `(${rate.toFixed(2)} msg/sec, ${this.stats.currentConnections} clients)`);
        }
    }

    // Setup graceful shutdown
    setupGracefulShutdown() {
        const shutdown = async (signal) => {
            log.info(`Received ${signal}, shutting down gracefully...`);
            
            // Close WebSocket server
            if (this.wss) {
                this.wss.close();
            }
            
            // Close HTTP server
            if (this.server) {
                this.server.close();
            }
            
            // Close RabbitMQ connection
            if (this.rabbitmqConnection) {
                try {
                    await this.rabbitmqConnection.close();
                    log.info('RabbitMQ connection closed');
                } catch (error) {
                    log.error(`Error closing RabbitMQ connection: ${error.message}`);
                }
            }
            
            const runtime = (Date.now() - this.stats.startTime) / 1000;
            log.info(`Dashboard server stopped. Runtime: ${runtime.toFixed(2)}s, ` +
                    `Messages processed: ${this.stats.messagesReceived}`);
            
            process.exit(0);
        };
        
        process.on('SIGINT', () => shutdown('SIGINT'));
        process.on('SIGTERM', () => shutdown('SIGTERM'));
    }

    // Start the dashboard server
    async start() {
        log.info('Starting Dashboard Server with RabbitMQ integration...');
        
        // Setup graceful shutdown
        this.setupGracefulShutdown();
        
        // Create HTTP and WebSocket servers
        this.createHttpServer();
        this.createWebSocketServer();
        
        // Start HTTP server
        this.server.listen(config.port, () => {
            log.info(`Dashboard server listening on port ${config.port}`);
            log.info(`WebSocket endpoint: ws://localhost:${config.port}/ws`);
            log.info(`Web interface: http://localhost:${config.port}`);
        });
        
        // Connect to RabbitMQ and start consuming
        if (await this.connectRabbitMQ()) {
            await this.startConsumingDecisions();
        } else {
            log.error('Failed to connect to RabbitMQ, dashboard will not receive decisions');
        }
        
        log.info('Dashboard server started successfully');
    }
}

// Start the server
const dashboard = new DashboardServer();
dashboard.start().catch(error => {
    console.error('Failed to start dashboard server:', error);
    process.exit(1);
});
