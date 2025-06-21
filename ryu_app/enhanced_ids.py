import time
import json
import requests
import websocket
import threading
from collections import defaultdict
import numpy as np
from sklearn.preprocessing import RobustScaler
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, tcp, udp, ether_types

class EnhancedIDSController(app_manager.RyuApp):
    
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    
    def __init__(self, *args, **kwargs):
        super(EnhancedIDSController, self).__init__(*args, **kwargs)
        self.flow_stats = defaultdict(dict)
        self.ml_api = "http://ml-model:5000/predict"
        self.ml_health_url = "http://ml-model:5000/health"
        self.ws_url = "ws://dashboard:8080/ws"
        self.ml_connected = False
        self.ws = None
        self.ws_connected = False
        
        # Add a startup delay to ensure services are ready
        self.logger.info("Starting Enhanced Ryu controller with initial delay...")
        time.sleep(5)
        
        # MAC address table for L2 switching
        self.mac_to_port = {}
        
        # Initialize RobustScaler
        try:
            with open('robust_scaler_params_2.json', 'r') as f:
                 params = json.load(f)
        
            self.scaler = RobustScaler(
                quantile_range=tuple(params['quantile_range']),
                with_centering=params['with_centering'],
                with_scaling=params['with_scaling']
            )  
            self.scaler.center_ = np.array(params['center_'])
            self.scaler.scale_ = np.array(params['scale_'])   
            self.scaler_fitted = True
            self.logger.info("Successfully loaded parameters from robust_scaler_params.json")
        except Exception as e:
            self.logger.error("Error loading scaler parameters: {0}".format(str(e)))
            self.logger.info("Creating a new RobustScaler as fallback")
            self.scaler = RobustScaler()
            self.scaler_fitted = False
            
        # Initialize WebSocket connection
        self.connect_dashboard()
            
        # Check ML model connectivity
        self.ml_connected = self.check_ml_model_connectivity()
        
        # Start background health check thread
        self.health_check_thread = threading.Thread(target=self.background_health_check)
        self.health_check_thread.daemon = True
        self.health_check_thread.start()
        self.logger.info("Background health check thread started")
    
    def connect_dashboard(self):
        """Connect to the dashboard WebSocket and handle connection errors"""
        try:
            self.ws = websocket.WebSocket()
            self.ws.connect(self.ws_url)
            self.ws_connected = True
            self.logger.info("Connected to dashboard WebSocket")
        except Exception as e:
            self.logger.error("Failed to connect to dashboard WebSocket: {0}".format(e))
            self.ws_connected = False    
        
    def background_health_check(self):
        """Background thread to periodically check ML model health"""
        check_interval = 30
        while True:
            self.ml_connected = self.check_ml_model_connectivity(quiet=True)
            time.sleep(check_interval)
    
    def check_ml_model_connectivity(self, quiet=False):
        """Check if ML model service is available with retries"""
        max_retries = 5
        retry_delay = 2
        retry_count = 0
        
        if not quiet:
            self.logger.info("Checking ML model connectivity...")
        
        while retry_count < max_retries:
            try:
                health_response = requests.get(self.ml_health_url, timeout=2.0)
                
                if health_response.status_code == 200:
                    health_data = health_response.json()
                    if not quiet:
                        self.logger.info("ML model service is healthy. Model type: {0}".format(health_data.get('model_type')))
                    elif not self.ml_connected:
                        self.logger.info("ML model connection restored")
                    return True
                else:
                    if not quiet:
                        self.logger.warning("ML model health check returned status code {0}".format(health_response.status_code))
                    
            except Exception as e:
                if not quiet:
                    self.logger.warning("ML model connection attempt {0} failed: {1}".format(retry_count+1, str(e)))
                elif retry_count == 0 and self.ml_connected:
                    self.logger.warning("ML model connection lost: {0}".format(str(e)))
            
            retry_count += 1
            if retry_count < max_retries:
                if not quiet:
                    self.logger.info("Retrying in {0} seconds... ({1}/{2})".format(retry_delay, retry_count, max_retries))
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
        
    def add_flow(self, datapath, priority, match, actions, buffer_id=None, idle_timeout=0, hard_timeout=0):
        """Add a flow entry to the switch."""
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

    def extract_features(self, pkt, flow_id):
        """Extract enhanced features with proper flow tracking"""
        # Extract packet headers
        eth = pkt.get_protocol(ethernet.ethernet)
        ip = pkt.get_protocol(ipv4.ipv4)
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        udp_pkt = pkt.get_protocol(udp.udp)
        transport = tcp_pkt or udp_pkt

        # Initialize feature vector with exactly 20 elements for the enhanced features
        features = [0.0] * 20
        
        # Get or initialize flow stats
        if flow_id not in self.flow_stats:
            self.flow_stats[flow_id] = {
                'start_time': time.time(),
                'last_packet_time': time.time(),
                'packet_count': 0,
                'tot_sum': 0,
                'syn_count': 0,
                'urg_count': 0,
                'fin_count': 0,
                'ack_count': 0,
                'packet_lengths': [],
                'incoming_lengths': [],
                'outgoing_lengths': [],
                'min_length': float('inf'),
                'max_length': 0,
                'rst_count': 0,
                'ack_flag_value': 0,
                'rst_flag_value': 0
            }
        
        flow_stats = self.flow_stats[flow_id]
        current_time = time.time()
        
        # Calculate IAT (Inter-Arrival Time) - Index 0
        features[0] = current_time - flow_stats['last_packet_time']
        
        # Update packet count
        flow_stats['packet_count'] += 1
        
        # Calculate packet length and update stats
        packet_length = len(pkt.data) if hasattr(pkt, 'data') else 0
        flow_stats['tot_sum'] += packet_length
        flow_stats['packet_lengths'].append(packet_length)
        
        # Update min and max packet lengths
        if packet_length < flow_stats['min_length']:
            flow_stats['min_length'] = packet_length
        if packet_length > flow_stats['max_length']:
            flow_stats['max_length'] = packet_length
        
        # Determine if packet is incoming or outgoing (simplified logic)
        if transport:
            if transport.dst_port > transport.src_port:  # Simplified direction detection
                flow_stats['incoming_lengths'].append(packet_length)
            else:
                flow_stats['outgoing_lengths'].append(packet_length)
        
        # Calculate flow duration
        flow_duration = current_time - flow_stats['start_time']
        
        # Header Length - Index 1
        header_length = 0
        if eth:
            header_length += 14  # Ethernet header
        if ip:
            header_length += (ip.header_length * 4)  # IP header (in bytes)
        if tcp_pkt:
            header_length += (tcp_pkt.offset * 4)  # TCP header (in bytes)
        elif udp_pkt:
            header_length += 8  # UDP header
        features[1] = header_length
        
        # Calculate packet rate - Index 2
        if flow_duration > 0:
            features[2] = float(flow_stats['packet_count']) / float(flow_duration)
        
        # Variance of packet lengths - Index 3
        if len(flow_stats['packet_lengths']) > 1:
            # Calculate variance for incoming or outgoing packets
            if len(flow_stats['incoming_lengths']) > 1:
                features[3] = np.var(flow_stats['incoming_lengths'])
            elif len(flow_stats['outgoing_lengths']) > 1:
                features[3] = np.var(flow_stats['outgoing_lengths'])
            else:
                features[3] = np.var(flow_stats['packet_lengths'])
        
        # URG count - Index 4
        features[4] = flow_stats['urg_count']
        
        # Tot sum - Index 5
        features[5] = flow_stats['tot_sum']
        
        # Duration (TTL) - Index 6
        if ip:
            features[6] = ip.ttl
        
        # SYN count - Index 7
        features[7] = flow_stats['syn_count']
        
        # Min packet length - Index 8
        features[8] = flow_stats['min_length'] if flow_stats['min_length'] != float('inf') else 0
        
        # Flow duration - Index 9
        features[9] = flow_duration
        
        # FIN count - Index 10
        features[10] = flow_stats['fin_count']
        
        # Covariance - Index 11
        if len(flow_stats['incoming_lengths']) > 0 and len(flow_stats['outgoing_lengths']) > 0:
            # Pad the shorter list to match lengths for covariance calculation
            min_len = min(len(flow_stats['incoming_lengths']), len(flow_stats['outgoing_lengths']))
            if min_len > 1:
                features[11] = np.cov(flow_stats['incoming_lengths'][:min_len], 
                                      flow_stats['outgoing_lengths'][:min_len])[0, 1]
        
        # Max packet length - Index 12
        features[12] = flow_stats['max_length']
        
        # ACK count - Index 13
        features[13] = flow_stats['ack_count']
        
        # TCP indicator - Index 14
        features[14] = 1 if (ip and ip.proto == 6) else 0
        
        # ACK flag value - Index 15
        features[15] = flow_stats['ack_flag_value']
        
        # Protocol Type - Index 16
        if ip:
            proto = ip.proto
            features[16] = proto if 1 <= proto <= 17 else -1
        else:
            features[16] = -1
        
        # UDP indicator - Index 17
        features[17] = 1 if (ip and ip.proto == 17) else 0
        
        # RST flag value - Index 18
        features[18] = flow_stats['rst_flag_value']
        
        # ICMP indicator - Index 19
        features[19] = 1 if (ip and ip.proto == 1) else 0
        
        # TCP flags and counts
        if tcp_pkt:
            # In Python 2.7, TCP flags are accessed via bits instead of attributes
            # TCP flags: SYN=0x02, ACK=0x10, FIN=0x01, URG=0x20, RST=0x04
            if tcp_pkt.bits & 0x02:  # SYN flag
                flow_stats['syn_count'] += 1
            if tcp_pkt.bits & 0x20:  # URG flag
                flow_stats['urg_count'] += 1
            if tcp_pkt.bits & 0x01:  # FIN flag
                flow_stats['fin_count'] += 1
            if tcp_pkt.bits & 0x10:  # ACK flag
                flow_stats['ack_count'] += 1
                flow_stats['ack_flag_value'] = 1
            if tcp_pkt.bits & 0x04:  # RST flag
                flow_stats['rst_count'] += 1
                flow_stats['rst_flag_value'] = 1
        
        # Update last packet time
        flow_stats['last_packet_time'] = current_time
        
        return features
    
    def preprocess_features(self, features):
        """Preprocess features before sending to ML model"""
        features_array = np.array(features)
        
        # Define which features are numerical and which are categorical
        # Based on user's specification, these indices are categorical:
        # TCP (index 14), ack_flag_number (index 15), Protocol Type (index 16),
        # UDP (index 17), rst_flag_number (index 18), ICMP (index 19)
        categorical_indices = [14, 15, 16, 17, 18, 19]
        
        # Create a boolean mask for numerical features - Python 2.7 compatible approach
        numerical_mask = np.ones(len(features_array), dtype=bool)
        for idx in categorical_indices:
            numerical_mask[idx] = False
        
        # Extract numerical and categorical features using the mask
        numerical_features = features_array[numerical_mask].reshape(1, -1)
        categorical_features = features_array[~numerical_mask].reshape(1, -1)
        
        # Apply RobustScaler to numerical features if fitted
        if self.scaler_fitted:
            scaled_numerical = self.scaler.transform(numerical_features)
        else:
            scaled_numerical = self.scaler.fit_transform(numerical_features)
            self.scaler_fitted = True
            self.logger.info("Fitted RobustScaler with current data (fallback mode)")
        
        # Reconstruct the feature array with scaled numerical features and original categorical features
        preprocessed = np.zeros(len(features_array))
        preprocessed[numerical_mask] = scaled_numerical.flatten()
        preprocessed[~numerical_mask] = categorical_features.flatten()
        
        return preprocessed.tolist()

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
        
        # Extract features with proper flow tracking
        features = self.extract_features(pkt, flow_id)
        
        # Apply preprocessing
        preprocessed_features = self.preprocess_features(features)
        
        # Skip ML model prediction if not connected
        if not self.ml_connected:
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
                response = requests.post(
                    self.ml_api,
                    json={'features': preprocessed_features},
                    timeout=1.0
                )
                result = response.json()
                is_attack = result.get('is_attack', False)
                attack_type = result.get('attack_type', 0)
                confidence = result.get('confidence', 0.0)
                ml_success = True
                
                # Log detailed information for debugging
                self.logger.info("Flow: {0}, Packet Count: {1}, Decision: {2}, Confidence: {3:.2f}".format(
                    flow_id, 
                    self.flow_stats[flow_id]['packet_count'],
                    'BLOCK' if is_attack else 'ALLOW',
                    confidence
                ))
                
                # Send decision to dashboard
                message = {
                    'timestamp': time.time() * 1000,
                    'flow_id': flow_id,
                    'packet_count': self.flow_stats[flow_id]['packet_count'],
                    'features': preprocessed_features,
                    'decision': 'BLOCK' if is_attack else 'ALLOW',
                    'attack_type': attack_type,
                    'confidence': confidence,
                }
                
                if self.ws_connected:
                    try:
                        self.ws.send(json.dumps(message))
                    except Exception as e:
                        self.logger.error("Failed to send message to dashboard: {0}".format(e))
                        self.ws_connected = False
                        self.connect_dashboard()
                
                # Decision logic
                if not is_attack:
                    self.logger.debug("Benign traffic detected. Confidence: {0:.2f}".format(confidence))
                    self.l2_switching(msg, datapath, in_port, eth, dst, src)
                else:
                    self.logger.info("Attack detected! Type: {0}, Confidence: {1:.2f}".format(attack_type, confidence))
                    self.logger.info("Dropping attack traffic from {0} to {1}".format(src, dst))
                    # Packet is dropped by not forwarding it
                    
            except Exception as e:
                retry_count += 1
                if retry_count < max_retries:
                    self.logger.warning("ML Model attempt {0} failed: {1}. Retrying...".format(retry_count, str(e)))
                    time.sleep(retry_delay)
                else:
                    self.logger.error("ML Model error after {0} attempts: {1}".format(max_retries, str(e)))
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
        
        # Install flow entry for efficiency
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id, idle_timeout=10)
                return
            else:
                self.add_flow(datapath, 1, match, actions, idle_timeout=10)
                
        # Send packet out
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
            
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)