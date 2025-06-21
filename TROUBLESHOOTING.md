# Troubleshooting Guide

## WebSocket Connection Issues

If you encounter WebSocket connection errors in the logs like:

```
websocket._exceptions.WebSocketBadStatusException: Handshake status 404 Not Found
```

This indicates that the Ryu controller is unable to connect to the dashboard's WebSocket server. Here are some steps to troubleshoot:

### 1. Check if Dashboard Container is Running

```bash
docker ps | grep dashboard
```

Make sure the dashboard container is up and running.

### 2. Verify WebSocket Server

The dashboard now uses a proper WebSocket server implementation. Check the logs to see if it started correctly:

```bash
docker logs dashboard
```

You should see a message like: `WebSocket server available at ws://localhost:8080/ws`

### 3. Test WebSocket Connection

You can test the WebSocket connection using a tool like `wscat`:

```bash
npm install -g wscat
wscat -c ws://localhost:8080/ws
```

### 4. Network Connectivity

Ensure that the containers can communicate with each other on the SDN network:

```bash
docker exec ryu-controller-custom ping -c 3 dashboard
```

### 5. Restart Services

If issues persist, try restarting the services:

```bash
docker-compose restart dashboard ryu-custom
```

## Note on Error Handling

The Ryu controller has been updated to handle WebSocket connection failures gracefully. If the dashboard is not available, the controller will continue to function without sending data to the dashboard.

This means:

1. The IDS functionality will still work (detecting and blocking attacks)
2. The dashboard visualization will not receive updates until the connection is established

You can check the Ryu controller logs to see the connection status:

```bash
docker logs ryu-controller-custom
```