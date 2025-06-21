import time
import json
import requests
import websocket
import threading
from collections import defaultdict
import numpy as np
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, tcp, udp, ether_types

class EnhancedIDSControllerNoScaling(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    
    def __init__(self, *args, **kwargs):
        super(EnhancedIDSControllerNoScaling, self).__init__(*args, **kwargs)
        self.flow_stats = defaultdict(dict)
        self.ml_api = "http://ml-model:5000/predict"
        self.ml_health_url = "http://ml-model:5000/health"
        self.ws_url = "ws://dashboard:8080/ws"
        self.ml_connected = False
        self.ws = None
        self.ws_connected = False
        self.mac_to_port = {}
        self.flow_windows = defaultdict(list)  # Store packets per flow
        self.flow_states = defaultdict(dict)   # Track flow statistics
        
        
        # Logging configuration
        self.message_count = 0
        self.log_file_path = '/app/network_logs.txt'
        self.max_messages = 1000
        
        # Initialize services
        self.logger.info("Starting Enhanced Ryu controller (No Scaling) with initial delay...")
        time.sleep(5)
        self._init_log_file()
        self.connect_dashboard()
        self.ml_connected = self.check_ml_model_connectivity()
        
        # Start background health check
        self.health_check_thread = threading.Thread(target=self.background_health_check)
        self.health_check_thread.daemon = True
        self.health_check_thread.start()
        self.logger.info("Background health check thread started")

    def _init_log_file(self):
        """Initialize or clear the log file"""
        try:
            with open(self.log_file_path, 'w') as f:
                f.write('Network Traffic Analysis Logs\n')
                f.write('----------------------------\n')
        except IOError as e:
            self.logger.error("Failed to create log file: {0}".format(str(e)))
    
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

        # For ICMP or other protocols without ports, use different flow ID format
        if protocol == 1:  # ICMP
            # Use ICMP type/code if available, or just IPs
            flow_id = "ICMP-{0}-{1}-{2}".format(src_ip, dst_ip, int(time.time() * 1000) // 1000)
        elif protocol == 6 or protocol == 17:  # TCP or UDP
            # Create a bidirectional flow ID (same for both directions)
            if src_ip < dst_ip or (src_ip == dst_ip and src_port < dst_port):
                flow_id = "{0}:{1}-{2}:{3}-{4}".format(src_ip, src_port, dst_ip, dst_port, protocol)
            else:
                flow_id = "{0}:{1}-{2}:{3}-{4}".format(dst_ip, dst_port, src_ip, src_port, protocol)
        else:
            # Other protocols
            flow_id = "PROTO{0}-{1}-{2}".format(protocol, src_ip, dst_ip)

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

    # Remove old extract_features and add new window-based feature extraction
    def extract_window_features(self, flow_id):
        """Calculate aggregated features for 100-packet window"""
        window = self.flow_windows[flow_id]
        features = [0.0] * 20  # Initialize feature vector

        # Timestamps for IAT and duration calculation
        timestamps = [pkt['time'] for pkt in window]
        features[0] = np.mean(np.diff(timestamps))  # IAT (Index 0)
        features[9] = timestamps[-1] - timestamps[0]  # Flow duration (Index 9)

        # Packet length statistics
        lengths = [pkt['length'] for pkt in window]
        features[5] = sum(lengths)  # Tot sum (Index 5)
        features[8] = min(lengths)  # Min (Index 8)
        features[12] = max(lengths)  # Max (Index 12)
        features[3] = np.var(lengths)  # Variance (Index 3)

        # Protocol and flag counts
        tcp_count = 0
        udp_count = 0
        icmp_count = 0
        syn_count = 0
        ack_count = 0
        rst_count = 0
        urg_count = 0
        fin_count = 0

        for pkt in window:
            if pkt['protocol'] == 6:  # TCP
                tcp_count += 1
                if 'tcp_flags' in pkt and pkt['tcp_flags'].get('SYN', 0):
                    syn_count += 1
                if 'tcp_flags' in pkt and pkt['tcp_flags'].get('ACK', 0):
                    ack_count += 1
                if 'tcp_flags' in pkt and pkt['tcp_flags'].get('RST', 0):
                    rst_count += 1
                if 'tcp_flags' in pkt and pkt['tcp_flags'].get('URG', 0):
                    urg_count += 1
                if 'tcp_flags' in pkt and pkt['tcp_flags'].get('FIN', 0):
                    fin_count += 1  # FIN count (Index 10)
            elif pkt['protocol'] == 17:  # UDP
                udp_count += 1
            elif pkt['protocol'] == 1:  # ICMP
                icmp_count += 1

        # Protocol indicators
        features[14] = 1 if tcp_count > 0 else 0  # TCP (Index 14)
        features[17] = 1 if udp_count > 0 else 0  # UDP (Index 17)
        features[19] = 1 if icmp_count > 0 else 0  # ICMP (Index 19)

        # Flag counts and values
        features[4] = urg_count  # URG count (Index 4)
        features[7] = syn_count  # SYN count (Index 7)
        features[13] = ack_count  # ACK count (Index 13)
        features[15] = 1 if ack_count > 0 else 0  # ACK flag value (Index 15)
        features[18] = 1 if rst_count > 0 else 0  # RST flag value (Index 18)

        # Header length approximation (Index 1)
        features[1] = np.mean([pkt.get('header_length', 0) for pkt in window])

        # Packet rate (Index 2)
        features[2] = 20 / features[9] if features[9] > 0 else 0

        # Duration (TTL) - use mode (Index 6)
        ttls = [pkt.get('ttl', 0) for pkt in window]
        features[6] = max(set(ttls), key=ttls.count) if ttls else 0

        # FIN count (Index 10) 
        features[10] = fin_count

        # Covariance (Index 11)
        # Separate incoming and outgoing packets based on port numbers
        incoming_lengths = []
        outgoing_lengths = []
        
        for pkt in window:
            if 'src_port' in pkt and 'dst_port' in pkt:
                if pkt['src_port'] < pkt['dst_port']:
                    incoming_lengths.append(pkt['length'])
                else:
                    outgoing_lengths.append(pkt['length'])
        
        # Calculate covariance if we have both incoming and outgoing packets
        if len(incoming_lengths) > 1 and len(outgoing_lengths) > 1:
            # Pad the shorter list to match lengths for covariance calculation
            min_len = min(len(incoming_lengths), len(outgoing_lengths))
            features[11] = np.cov(incoming_lengths[:min_len], outgoing_lengths[:min_len])[0, 1]
        else:
            features[11] = 0

        # Protocol type (Index 16) - use most frequent
        protocols = [pkt['protocol'] for pkt in window]
        features[16] = max(set(protocols), key=protocols.count) if protocols else -1

        return features

    # Remove old packet_in_handler and add revised version
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

        # Parse packet for window storage
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        udp_pkt = pkt.get_protocol(udp.udp)

        packet_data = {
            'time': time.time(),
            'length': len(pkt),
            'protocol': ip_pkt.proto if ip_pkt else 0,
            'ttl': ip_pkt.ttl if ip_pkt else 0,
            'header_length': self.calculate_header_length(pkt),
            'src_port': tcp_pkt.src_port if tcp_pkt else (udp_pkt.src_port if udp_pkt else 0),
            'dst_port': tcp_pkt.dst_port if tcp_pkt else (udp_pkt.dst_port if udp_pkt else 0)
        }

        # Extract TCP flags if available
        if tcp_pkt:
            packet_data['tcp_flags'] = {
                'SYN': 1 if tcp_pkt.bits & 0x02 else 0,
                'ACK': 1 if tcp_pkt.bits & 0x10 else 0,
                'RST': 1 if tcp_pkt.bits & 0x04 else 0,
                'URG': 1 if tcp_pkt.bits & 0x20 else 0
            }

        # Store packet in flow window
        if flow_id not in self.flow_windows:
            self.flow_windows[flow_id] = []
        self.flow_windows[flow_id].append(packet_data)

        # Forward packet immediately (don't wait for analysis)
        self.forward_without_install(msg, datapath, in_port, eth, dst, src)

        # Process window when we have 100 packets
        if len(self.flow_windows[flow_id]) >= 20:
            try:
                # Extract aggregated features
                features = self.extract_window_features(flow_id)
                preprocessed_features = features

                if not self.ml_connected:
                    self.logger.debug("ML model not connected, skipping prediction")
                    self.flow_windows[flow_id] = []
                    return

                response = requests.post(
                    self.ml_api,
                    json={'features': preprocessed_features},
                    timeout=1.0
                )
                result = response.json()
                is_attack = result.get('is_attack', False)
                attack_type = result.get('attack_type', 0)
                confidence = result.get('confidence', 0.0)

                if is_attack:
                    self.logger.info("DDoS attack detected! Type: {}, Confidence: {:.2f}".format(attack_type, confidence))
                    self.install_drop_rule(datapath, flow_id)
                else:
                    self.logger.debug("Benign traffic. Confidence: {:.2f}".format(confidence))

                if self.ws_connected:
                    message = {
                        'timestamp': time.time() * 1000,
                        'flow_id': flow_id,
                        'decision': 'BLOCK' if is_attack else 'ALLOW',
                        'attack_type': attack_type,
                        'confidence': confidence,
                    }
                    print("features sent ot dashboard:", preprocessed_features)
                    try:
                        self.ws.send(json.dumps(message))
                    except Exception as e:
                        self.logger.error("Failed to send to dashboard: {}".format(e))
                        self.ws_connected = False

            except Exception as e:
                self.logger.error("Error processing window: {}".format(e))
            finally:
                self.flow_windows[flow_id] = []

    # Add helper functions
    def calculate_header_length(self, pkt):
        """Calculate total header length for a packet"""
        header_length = 0
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        udp_pkt = pkt.get_protocol(udp.udp)

        if eth_pkt:
            header_length += 14  # Ethernet header
        if ip_pkt:
            header_length += (ip_pkt.header_length * 4)  # IP header
        if tcp_pkt:
            header_length += (tcp_pkt.offset * 4)  # TCP header
        elif udp_pkt:
            header_length += 8  # UDP header

        return header_length

    def forward_without_install(self, msg, datapath, in_port, eth, dst, src):
        """Forward packet without installing flow entry"""
        dpid = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        if dpid in self.mac_to_port and dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=data
        )
        datapath.send_msg(out)

    def install_drop_rule(self, datapath, flow_id):
        """Install drop rule for malicious flow"""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Extract flow info from flow_id (simplified)
        parts = flow_id.split('-')
        if len(parts) < 5:
            self.logger.warning("Invalid flow_id format: {}".format(flow_id))
            return

        try:
            parser = datapath.ofproto_parser
            match = parser.OFPMatch(
                eth_type=0x0800,  # IPv4
                ipv4_src=parts[0],
                ipv4_dst=parts[1],
                ip_proto=int(parts[4])
            )

            if int(parts[4]) in [6, 17]:  # TCP or UDP
                match.tcp_src = int(parts[2])
                match.tcp_dst = int(parts[3])

            self.add_flow(
                datapath, 
                priority=10, 
                match=match, 
                actions=[],  # No actions = drop
                idle_timeout=60, 
                hard_timeout=120
            )
            self.logger.info("Installed drop rule for {}".format(flow_id))

        except Exception as e:
            self.logger.error("Error installing drop rule: {}".format(e))
