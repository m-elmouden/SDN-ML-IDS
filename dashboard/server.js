const http = require('http');
const fs = require('fs');
const path = require('path');
const WebSocket = require('ws');

// Create HTTP server
const server = http.createServer((req, res) => {
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

// Create WebSocket server
const wss = new WebSocket.Server({ server, path: '/ws' });

// WebSocket connection handler
wss.on('connection', (ws) => {
  console.log('Client connected to WebSocket');
  
  // Send initial data
  const initialData = {
    timestamp: Date.now(),
    features: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    packet_count: 0,
    decision: 'ALLOW',
    attack_type: 0,  // 0 for benign, 1-12 for attack types
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
      
      // Add some debugging info
      console.log('Received message:', data.type || 'unknown type', 'flow_id:', data.flow_id || 'none');
      
      // Process and normalize the data for consistent display
      
      // For traffic messages, add packet_count if missing
      if (!data.packet_count && data.features && data.features.length > 5) {
        data.packet_count = data.features[5];
      }
      
      // For decision messages, ensure attack_type is defined
      if (typeof data.attack_type === 'undefined') {
        if (data.is_attack !== undefined) {
          data.attack_type = data.is_attack ? 1 : 0;
        } else if (data.decision === 'BLOCK') {
          data.attack_type = 1; // Assume type 1 if blocking but no specific type
        }
      }
      
      // Ensure we have a decision value
      if (!data.decision) {
        if (data.is_attack !== undefined) {
          data.decision = data.is_attack ? 'BLOCK' : 'ALLOW';
        } else if (data.attack_type > 0) {
          data.decision = 'BLOCK';
        } else {
          data.decision = 'ALLOW';
        }
      }
      
      // Log enhanced message
      console.log('Enhanced message:', {
        decision: data.decision,
        attack_type: data.attack_type,
        flow_id: data.flow_id || 'none'
      });
      
      // Forward the enhanced message to all connected clients
      wss.clients.forEach((client) => {
        if (client.readyState === WebSocket.OPEN) {
          client.send(JSON.stringify(data));
        }
      });
    } catch (error) {
      console.error('Error processing message:', error);
    }
  });
  
  // Handle disconnection
  ws.on('close', () => {
    console.log('Client disconnected from WebSocket');
  });
});

// Start server
const PORT = process.env.PORT || 8080;
const HOST = process.env.HOST_IP || '0.0.0.0';  // Listen on all interfaces
server.listen(PORT, HOST, () => {
  console.log(`Server running on ${HOST}:${PORT}`);
  console.log(`WebSocket server available at ws://${HOST}:${PORT}/ws`);
});