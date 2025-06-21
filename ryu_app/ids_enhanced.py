#!/usr/bin/env python
# -*- coding: utf-8 -*-

# This file is compatible with Python 2.7

# Import division from __future__ to ensure consistent division behavior
from __future__ import division

import time
import json
import requests
import websocket
import threading
import os
from collections import defaultdict
import numpy as np
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, tcp, udp, ether_types

# Remove global variables and use class variables instead

class EnhancedIDSController(app_manager.RyuApp):
    
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    
    def __init__(self, *args, **kwargs):
        super(EnhancedIDSController, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.flow_stats = {}
        self.blocked_flows = set()
        self.total_packets_processed = 0
        
        # ML model connection settings
        self.ml_api = os.environ.get('ML_API_URL', 'http://localhost:5000/predict')
        self.ml_connected = False
        self.ml_health_check_interval = 5  # seconds
        self.ml_health_check_thread = None
        
        # Dashboard connection settings
        self.dashboard_ws = None
        self.dashboard_ws_url = os.environ.get('DASHBOARD_WS_URL', 'ws://localhost:8080/ws')
        self.dashboard_reconnect_interval = 5  # seconds
        self.dashboard_reconnect_thread = None
        
        # Start background threads
        self.start_ml_health_check()
        self.connect_dashboard()
            
        # Check ML model connectivity
        self.ml_connected = self.check_ml_model_connectivity()
        
        # Start health check thread
        self.health_check_thread = threading.Thread(target=self.background_health_check)
        self.health_check_thread.daemon = True
        self.health_check_thread.start()
        
        self.logger.info("Controller initialized")
    
    def send_to_dashboard(self, message):
        """Send message to dashboard with error handling"""
        try:
            # Create connection if doesn't exist
            if not hasattr(self, 'dashboard_ws') or not self.dashboard_ws:
                self.connect_dashboard()
            
            # Skip if still not connected
            if not hasattr(self, 'dashboard_ws') or not self.dashboard_ws:
                return
            
            self.dashboard_ws.send(json.dumps(message))
        except Exception as e:
            self.logger.error("Dashboard send failed: %s" % e)
            self.connect_dashboard()
    
    def connect_dashboard(self):
        """Connect to the dashboard WebSocket and handle connection errors"""
        try:
            if hasattr(self, 'dashboard_ws') and self.dashboard_ws :
                try:
                    self.dashboard_ws.close()
                except:
                    pass
            self.dashboard_ws = websocket.create_connection(
            self.dashboard_ws_url,
            timeout=3  # Add timeout to prevent hanging
        )
            self.logger.info("Connected to dashboard WebSocket")
            # Reset packet counter for each new dashboard connection
            self.total_packets_processed = 0
            self.logger.info("Connected to dashboard WebSocket at %s" % self.dashboard_ws_url)
            self.logger.info("Reset packet counter for new dashboard connection")
        except Exception as e:
            self.logger.error("Failed to connect to dashboard WebSocket: %s" % e)
            # Schedule reconnection attempt
            threading.Timer(self.dashboard_reconnect_interval, self.connect_dashboard).start()
        
    def start_ml_health_check(self):
        """Start background thread to periodically check ML model health"""
        if self.ml_health_check_thread is None or not self.ml_health_check_thread.is_alive():
            self.ml_health_check_thread = threading.Thread(target=self.background_health_check)
            self.ml_health_check_thread.daemon = True
            self.ml_health_check_thread.start()
            self.logger.info("Started ML health check thread")
    
    def background_health_check(self):
        """Background thread to periodically check ML model health"""
        while True:
            try:
                # Extract the base URL from the ML API endpoint
                base_url = '/'.join(self.ml_api.split('/')[:-1])
                health_url = base_url + '/health'
                
                response = requests.get(health_url, timeout=2.0)
                if response.status_code == 200:
                    self.ml_connected = True
                    self.logger.debug("ML model is connected and healthy")
                else:
                    self.ml_connected = False
                    self.logger.warning("ML model health check failed with status code: %d" % response.status_code)
            except Exception as e:
                self.ml_connected = False
                self.logger.warning("ML model health check failed: %s" % str(e))
            
            time.sleep(self.ml_health_check_interval)
    
    def check_ml_model_connectivity(self, quiet=False):
        """Check if ML model service is available with retries"""
        max_retries = 5
        retry_delay = 2
        retry_count = 0
        
        if not quiet:
            self.logger.info("Checking ML model connectivity...")
        
        # Extract the base URL from the ML API endpoint
        base_url = '/'.join(self.ml_api.split('/')[:-1])
        health_url = base_url + '/health'
        
        while retry_count < max_retries:
            try:
                health_response = requests.get(health_url, timeout=2.0)
                
                if health_response.status_code == 200:
                    health_data = health_response.json()
                    if not quiet:
                        self.logger.info("ML model service is healthy. Model type: %s" % 
                            health_data.get('model_type', 'unknown'))
                    elif not self.ml_connected:
                        self.logger.info("ML model connection restored")
                    return True
                else:
                    if not quiet:
                        self.logger.warning("ML model health check returned status code %d" % 
                            health_response.status_code)
                    
            except Exception as e:
                if not quiet:
                    self.logger.warning("ML model connection attempt %d failed: %s" % (
                        retry_count+1, str(e)))
                elif retry_count == 0 and self.ml_connected:
                    self.logger.warning("ML model connection lost: %s" % str(e))
            
            retry_count += 1
            if retry_count < max_retries:
                if not quiet:
                    self.logger.info("Retrying in {0} seconds... ({1}/{2})".format(
                        retry_delay, retry_count, max_retries))
                time.sleep(retry_delay)
        
        if not quiet:
            self.logger.error("Failed to connect to ML model after {0} attempts".format(max_retries))
            self.logger.info("Controller will continue and use L2 switching as fallback")
        return False
            
    def get_flow_id(self, pkt):
        """Generate a unique identifier for a flow based on packet information"""
        eth = pkt.get_protocol(ethernet.ethernet)
        ip = pkt.get_protocol(ipv4.ipv4)
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        udp_pkt = pkt.get_protocol(udp.udp)
        
        # Default values
        src_ip = dst_ip = "0.0.0.0"
        src_port = dst_port = 0
        protocol = 0
        
        if ip:
            src_ip = ip.src
            dst_ip = ip.dst
            protocol = ip.proto
            
        if tcp_pkt:
            src_port = tcp_pkt.src_port
            dst_port = tcp_pkt.dst_port
        elif udp_pkt:
            src_port = udp_pkt.src_port
            dst_port = udp_pkt.dst_port
            
        # Create a bidirectional flow ID (same for both directions)
        if src_ip < dst_ip or (src_ip == dst_ip and src_port < dst_port):
            flow_id = "{0}:{1}-{2}:{3}-{4}".format(src_ip, src_port, dst_ip, dst_port, protocol)
        else:
            flow_id = "{0}:{1}-{2}:{3}-{4}".format(dst_ip, dst_port, src_ip, src_port, protocol)
            
        return flow_id
            
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Install table-miss flow entry
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        
    def add_flow(self, datapath, priority, match, actions, buffer_id=None, idle_timeout=30, hard_timeout=0):
        """Add a flow entry to the switch with shorter timeout"""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst, idle_timeout=idle_timeout,
                                    hard_timeout=hard_timeout)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst,
                                    idle_timeout=idle_timeout,
                                    hard_timeout=hard_timeout)
        datapath.send_msg(mod)

    def extract_features(self, pkt, msg, flow_id):
        """Extract enhanced features with proper flow tracking - Python 2.7 Compatible"""
        # Extract packet headers
        eth = pkt.get_protocol(ethernet.ethernet)
        ip = pkt.get_protocol(ipv4.ipv4)
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        udp_pkt = pkt.get_protocol(udp.udp)
        transport = tcp_pkt or udp_pkt

        # Get actual packet length from message data
        packet_length = len(msg.data)
        current_time = time.time()
        
        # Get or initialize flow stats
        if flow_id not in self.flow_stats:
            self.flow_stats[flow_id] = {
                'start_time': current_time,
                'last_packet_time': current_time,
                'packet_count': 0,
                'tot_sum': 0,
                'syn_count': 0,
                'urg_count': 0,
                'fin_count': 0,
                'ack_count': 0,
                'rst_count': 0,
                'packet_lengths': [],
                'forward_lengths': [],  # Client to server
                'backward_lengths': [],  # Server to client
                'min_length': float('inf'),
                'max_length': 0,
                'ack_flag_value': 0,
                'rst_flag_value': 0,
                'flow_src_ip': None,
                'flow_src_port': None
            }
        
        flow_stats = self.flow_stats[flow_id]
        
        # FIRST: Process TCP flags for current packet (before calculating features)
        if tcp_pkt:
            flags = tcp_pkt.bits
            # TCP flag constants
            TCP_SYN = 0x02
            TCP_ACK = 0x10
            TCP_FIN = 0x01
            TCP_URG = 0x20
            TCP_RST = 0x04
            
            # Check flags using bitwise operations
            if flags & TCP_SYN:
                flow_stats['syn_count'] += 1
            if flags & TCP_URG:
                flow_stats['urg_count'] += 1
            if flags & TCP_FIN:
                flow_stats['fin_count'] += 1
                # FIN packet indicates connection termination
                self.logger.debug("FIN packet detected for flow %s" % flow_id)
            if flags & TCP_ACK:
                flow_stats['ack_count'] += 1
                flow_stats['ack_flag_value'] = 1
            if flags & TCP_RST:
                flow_stats['rst_count'] += 1
                flow_stats['rst_flag_value'] = 1
                # RST packet indicates connection reset
                self.logger.debug("RST packet detected for flow %s" % flow_id)
        
        # Determine flow direction properly
        if ip and transport:
            # Initialize flow direction on first packet
            if flow_stats['flow_src_ip'] is None:
                flow_stats['flow_src_ip'] = ip.src
                flow_stats['flow_src_port'] = transport.src_port
            
            # Determine if this packet is forward or backward
            is_forward = (ip.src == flow_stats['flow_src_ip'] and 
                         transport.src_port == flow_stats['flow_src_port'])
            
            if is_forward:
                flow_stats['forward_lengths'].append(packet_length)
            else:
                flow_stats['backward_lengths'].append(packet_length)
        
        # Update packet statistics
        flow_stats['packet_count'] += 1
        flow_stats['tot_sum'] += packet_length
        flow_stats['packet_lengths'].append(packet_length)
        
        # Update min and max packet lengths
        if packet_length < flow_stats['min_length']:
            flow_stats['min_length'] = packet_length
        if packet_length > flow_stats['max_length']:
            flow_stats['max_length'] = packet_length
        
        # Calculate flow duration
        flow_duration = current_time - flow_stats['start_time']
        
        # Initialize feature vector with exactly 20 elements
        features = [0.0] * 20
        
        # Index 0: IAT (Inter-Arrival Time)
        features[0] = current_time - flow_stats['last_packet_time']
        
        # Index 1: Header Length
        header_length = 0
        if eth:
            header_length += 14  # Ethernet header
        if ip:
            header_length += (ip.header_length * 4)  # IP header
        if tcp_pkt:
            header_length += (tcp_pkt.offset * 4)  # TCP header
        elif udp_pkt:
            header_length += 8  # UDP header
        features[1] = header_length
        
        # Index 2: Packet rate
        if flow_duration > 0:
            # Ensure floating point division in Python 2.7
            features[2] = float(flow_stats['packet_count']) / float(flow_duration)
        
        # Index 3: Variance of packet lengths
        if len(flow_stats['backward_lengths']) > 1:
            features[3] = np.var(flow_stats['backward_lengths'])
        elif len(flow_stats['forward_lengths']) > 1:
            features[3] = np.var(flow_stats['forward_lengths'])
        elif len(flow_stats['packet_lengths']) > 1:
            features[3] = np.var(flow_stats['packet_lengths'])
        
        # Index 4: URG count
        features[4] = flow_stats['urg_count']
        
        # Index 5: Total sum of packet lengths
        features[5] = flow_stats['tot_sum']
        
        # Index 6: TTL (Time To Live)
        if ip:
            features[6] = ip.ttl
        
        # Index 7: SYN count
        features[7] = flow_stats['syn_count']
        
        # Index 8: Min packet length
        features[8] = flow_stats['min_length'] if flow_stats['min_length'] != float('inf') else 0
        
        # Index 9: Flow duration
        features[9] = flow_duration
        
        # Index 10: FIN count - Important for RST/FIN attacks
        features[10] = flow_stats['fin_count']
        
        # Index 11: Covariance (with proper error handling)
        if (len(flow_stats['forward_lengths']) > 1 and 
            len(flow_stats['backward_lengths']) > 1):
            try:
                min_len = min(len(flow_stats['forward_lengths']), 
                             len(flow_stats['backward_lengths']))
                if min_len > 1:
                    forward_subset = flow_stats['forward_lengths'][:min_len]
                    backward_subset = flow_stats['backward_lengths'][:min_len]
                    cov_matrix = np.cov(forward_subset, backward_subset)
                    features[11] = cov_matrix[0, 1]
            except Exception:
                features[11] = 0.0
        
        # Index 12: Max packet length
        features[12] = flow_stats['max_length']
        
        # Index 13: ACK count
        features[13] = flow_stats['ack_count']
        
        # Index 14: TCP indicator
        features[14] = 1 if (ip and ip.proto == 6) else 0
        
        # Index 15: ACK flag value
        features[15] = flow_stats['ack_flag_value']
        
        # Index 16: Protocol Type
        if ip:
            features[16] = ip.proto
        else:
            features[16] = 0
        
        # Index 17: UDP indicator
        features[17] = 1 if (ip and ip.proto == 17) else 0
        
        # Index 18: RST flag value - Important for RST/FIN attacks
        features[18] = flow_stats['rst_flag_value']
        
        # Index 19: ICMP indicator
        features[19] = 1 if (ip and ip.proto == 1) else 0
        
        # Update last packet time
        flow_stats['last_packet_time'] = current_time
        
        # Check for potential RST/FIN attack pattern
        if flow_stats['rst_count'] > 0 and flow_stats['fin_count'] > 0:
            self.logger.debug("Potential RST/FIN attack pattern detected in flow {0}".format(flow_id))
        
        return features
    
    def preprocess_features(self, features):
        """Preprocess features before sending to ML model - No scaling version"""
        features_array = np.array(features)
        return features_array.tolist()

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        
        # Ignore LLDP and IPv6 packets
        if eth.ethertype == ether_types.ETH_TYPE_LLDP or eth.ethertype == ether_types.ETH_TYPE_IPV6:
            return
            
        dst = eth.dst
        src = eth.src
        dpid = datapath.id
        
        # Learn MAC address
        if dpid not in self.mac_to_port:
            self.mac_to_port[dpid] = {}
        self.mac_to_port[dpid][src] = in_port
        
        # Get consistent flow ID
        flow_id = self.get_flow_id(pkt)
        
        # Increment the total packet counter
        self.total_packets_processed += 1
        
        # Extract features with proper flow tracking
        features = self.extract_features(pkt, msg, flow_id)
        
        # Apply preprocessing (no scaling in this version)
        preprocessed_features = self.preprocess_features(features)
        
        # Check if this flow has been previously blocked
        if flow_id in self.blocked_flows:
            # Get the attack type from flow stats or default to RSTFINFlood
            attack_type = self.flow_stats[flow_id].get('attack_type', 6)  # Default to RSTFINFlood
            
            # Send information to dashboard about this blocked flow
            message = {
                'type': 'detection',
                'timestamp': int(time.time() * 1000),
                'flow_id': flow_id,
                'packet_count': self.flow_stats[flow_id]['packet_count'],
                'features': preprocessed_features,
                'decision': 'BLOCK',
                'attack_type': attack_type,
                'confidence': 0.99,
                'flow_duration': features[9],
                'total_packets': self.total_packets_processed
            }
            
            self.logger.debug("Blocked flow detected: %s, attack type: %s" % (flow_id, attack_type))
            self.send_to_dashboard(message)
            return
        
        # Check for RST/FIN attack pattern directly
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        rst_fin_attack = False
        attack_type = 0
        
        # Check if this is a potential RST/FIN attack based on flow statistics
        if tcp_pkt and self.flow_stats[flow_id]['rst_count'] > 0 and self.flow_stats[flow_id]['fin_count'] > 0:
            rst_fin_attack = True
            attack_type = 6  # RSTFINFlood attack type
            self.logger.warning("RST/FIN attack pattern detected in flow %s" % flow_id)
        
        # Skip ML model prediction if not connected
        if not self.ml_connected:
            if rst_fin_attack:
                # Block the RST/FIN attack even without ML model
                self.logger.info("Blocking RST/FIN attack without ML model: %s" % flow_id)
                
                # Store attack type in flow stats
                self.flow_stats[flow_id]['attack_type'] = attack_type
                
                # Add to blocked flows set
                self.blocked_flows.add(flow_id)
                
                # Send decision to dashboard
                message = {
                    'type': 'detection',
                    'timestamp': time.time() * 1000,
                    'flow_id': flow_id,
                    'packet_count': self.flow_stats[flow_id]['packet_count'],
                    'features': preprocessed_features,
                    'decision': 'BLOCK',
                    'attack_type': attack_type,
                    'confidence': 0.95,  # High confidence for direct detection
                    'flow_duration': features[9],
                    'total_packets': self.total_packets_processed
                }
                
                self.send_to_dashboard(message)
                return
            else:
                self.logger.debug("ML model not connected, using L2 switching")
                self.l2_switching(msg, datapath, in_port, eth, dst, src)
                return
            
        # Send to ML model with retry mechanism
        max_retries = 3
        retry_delay = 1
        retry_count = 0
        ml_success = False
        
        while retry_count < max_retries and not ml_success:
            try:
                # Ensure JSON payload is properly formatted for Python 2.7
                payload = {'features': preprocessed_features}
                response = requests.post(
                    self.ml_api,
                    json=payload,
                    timeout=1.0
                )
                result = response.json()
                is_attack = result.get('is_attack', False)
                attack_type = result.get('attack_type', 0)
                confidence = result.get('confidence', 0.0)
                
                # If we detect RST/FIN patterns but ML doesn't classify it as an attack,
                # override the decision to ensure RST/FIN attacks are caught
                if rst_fin_attack and not is_attack:
                    self.logger.warning("Overriding ML decision for RST/FIN attack pattern in flow %s" % flow_id)
                    is_attack = True
                    attack_type = 6  # RSTFINFlood attack type
                    confidence = 0.95  # High confidence for direct detection
                
                ml_success = True
                
                # Log detailed information for debugging
                self.logger.info("Flow: %s, Packet Count: %d, Decision: %s, Confidence: %.2f, Attack Type: %s" % (
                    flow_id, 
                    self.flow_stats[flow_id]['packet_count'],
                    'BLOCK' if is_attack else 'ALLOW',
                    confidence,
                    attack_type
                ))
                
                # Always send decision to dashboard regardless of packet count
                message = {
                    'type': 'detection',
                    'timestamp': time.time() * 1000,
                    'flow_id': flow_id,
                    'packet_count': self.flow_stats[flow_id]['packet_count'],
                    'features': preprocessed_features,
                    'decision': 'BLOCK' if is_attack else 'ALLOW',
                    'attack_type': attack_type,
                    'confidence': confidence,
                    'flow_duration': features[9],
                    'total_packets': self.total_packets_processed
                }
                
                self.send_to_dashboard(message)
                
                # Decision logic
                if not is_attack:
                    self.logger.debug("Benign traffic detected. Confidence: %.2f" % confidence)
                    self.l2_switching(msg, datapath, in_port, eth, dst, src)
                else:
                    self.logger.info("ML model detected attack: %s with confidence %.2f" % (attack_type, confidence))
                    self.logger.info("Blocking flow: %s" % flow_id)
                    
                    # Store attack type in flow stats
                    self.flow_stats[flow_id]['attack_type'] = attack_type
                    
                    # Add to blocked flows set
                    self.blocked_flows.add(flow_id)
                    
                    # Install a drop rule for this flow to prevent future packets
                    ip_pkt = pkt.get_protocol(ipv4.ipv4)
                    if ip_pkt:
                        drop_match = parser.OFPMatch(
                            eth_type=ether_types.ETH_TYPE_IP,
                            ipv4_src=ip_pkt.src,
                            ipv4_dst=ip_pkt.dst
                        )
                        # No actions = drop
                        self.add_flow(datapath, 100, drop_match, [], 
                                    idle_timeout=60, hard_timeout=120)
                        self.logger.info("Installed drop rule for %s -> %s" % (
                            ip_pkt.src, ip_pkt.dst))
                        
            except Exception as e:
                retry_count += 1
                if retry_count < max_retries:
                    self.logger.warning("ML Model attempt %d failed: %s. Retrying..." % (
                        retry_count, str(e)))
                    time.sleep(retry_delay)
                else:
                    self.logger.error("ML Model error after %d attempts: %s" % (
                        max_retries, str(e)))
                    self.logger.info("Falling back to L2 switching")
                    self.l2_switching(msg, datapath, in_port, eth, dst, src)

    def l2_switching(self, msg, datapath, in_port, eth, dst, src):
        """Perform L2 switching for benign traffic."""
        dpid = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        # Determine output port
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD
            
        actions = [parser.OFPActionOutput(out_port)]
        
        # Install flow entry for efficiency with shorter timeout
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id, idle_timeout=30)
                return
            else:
                self.add_flow(datapath, 1, match, actions, idle_timeout=30)
                
        # Send packet out
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
            
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)