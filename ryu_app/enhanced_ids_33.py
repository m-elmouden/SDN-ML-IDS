
# this file is python 2.7 compatible


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
from ryu.lib.packet import arp, dhcp, icmp, ipv6
# dns module is not available in Ryu 4.31, implementing DNS detection differently

class EnhancedIDSController33(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    
    def __init__(self, *args, **kwargs):
        super(EnhancedIDSController33, self).__init__(*args, **kwargs)
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
        
        # Define feature names for reference
        self.feature_names = [
            'flow_duration',      # Index 0
            'Protocol_Type',      # Index 1
            'Duration',           # Index 2
            'Rate',               # Index 3
            'Drate',              # Index 4
            'fin_flag_number',    # Index 5
            'syn_flag_number',    # Index 6
            'rst_flag_number',    # Index 7
            'psh_flag_number',    # Index 8
            'ack_flag_number',    # Index 9
            'ece_flag_number',    # Index 10
            'cwr_flag_number',    # Index 11
            'ack_count',          # Index 12
            'syn_count',          # Index 13
            'fin_count',          # Index 14
            'urg_count',          # Index 15
            'HTTP',               # Index 16
            'HTTPS',              # Index 17
            'DNS',                # Index 18
            'Telnet',             # Index 19
            'SMTP',               # Index 20
            'SSH',                # Index 21
            'IRC',                # Index 22
            'TCP',                # Index 23
            'UDP',                # Index 24
            'DHCP',               # Index 25
            'ARP',                # Index 26
            'ICMP',               # Index 27
            'IPv',                # Index 28
            'LLC',                # Index 29
            'Tot_sum',            # Index 30
            'IAT',                # Index 31
            'Number'              # Index 32
        ]
        
        # Logging configuration
        self.message_count = 0
        self.log_file_path = '/app/network_logs.txt'
        self.max_messages = 1000
        
        # Application port mappings for protocol detection
        self.port_mappings = {
            'HTTP': [80, 8080],
            'HTTPS': [443, 8443],
            'DNS': [53],
            'Telnet': [23],
            'SMTP': [25, 587],
            'SSH': [22],
            'IRC': [194, 6667, 6697]
        }
        
        # Initialize services
        self.logger.info("Starting Enhanced IDS Controller (33 Features) with initial delay...")
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

    def detect_application_protocol(self, pkt, src_port, dst_port):
        """Detect application layer protocol based on port numbers and packet content"""
        protocols = {
            'HTTP': 0,
            'HTTPS': 0,
            'DNS': 0,
            'Telnet': 0,
            'SMTP': 0,
            'SSH': 0,
            'IRC': 0,
            'DHCP': 0
        }
          # Check if packet contains any of these protocols
        if pkt.get_protocol(dhcp.dhcp):
            protocols['DHCP'] = 1
            
        # DNS detection based on port (since dns module isn't available)
        if src_port == 53 or dst_port == 53:
            protocols['DNS'] = 1
            
        # Check port-based protocol detection
        for proto, ports in self.port_mappings.items():
            if src_port in ports or dst_port in ports:
                protocols[proto] = 1
                
        return protocols

    def extract_window_features(self, flow_id):
        """Calculate all 33 flow features for a window of packets"""
        window = self.flow_windows[flow_id]
        
        if not window:
            return [0.0] * 33
            
        # Initialize feature vector with 33 features
        features = [0.0] * 33
        
        # Get timestamps for time-based calculations
        timestamps = [pkt['time'] for pkt in window]
        
        # 0. flow_duration - Time between first and last packet
        features[0] = timestamps[-1] - timestamps[0] if len(timestamps) > 1 else 0
        
        # Protocol counters for protocol type detection
        tcp_count = 0
        udp_count = 0
        icmp_count = 0
        arp_count = 0
        ip_count = 0
        llc_count = 0
        dhcp_count = 0
        http_count = 0
        https_count = 0
        dns_count = 0
        telnet_count = 0
        smtp_count = 0
        ssh_count = 0
        irc_count = 0
        
        # Flag counters
        syn_count = 0
        ack_count = 0
        fin_count = 0
        rst_count = 0
        psh_count = 0
        urg_count = 0
        ece_count = 0
        cwr_count = 0
        
        # For inbound/outbound packet rates
        inbound_packets = 0
        outbound_packets = 0
        first_seen_src_ip = None
        first_seen_src_port = None
        
        # Packet length statistics for total sum
        packet_lengths = []
        
        # Process each packet in the window
        for pkt in window:
            # Count protocols
            proto = pkt.get('protocol', 0)
            if proto == 6:  # TCP
                tcp_count += 1
            elif proto == 17:  # UDP
                udp_count += 1
            elif proto == 1:  # ICMP
                icmp_count += 1
                
            # Count IP packets
            if proto > 0:
                ip_count += 1
                
            # Extract packet lengths
            packet_lengths.append(pkt['length'])
                
            # Get application protocols
            if 'app_protocols' in pkt:
                http_count += pkt['app_protocols'].get('HTTP', 0)
                https_count += pkt['app_protocols'].get('HTTPS', 0)
                dns_count += pkt['app_protocols'].get('DNS', 0)
                telnet_count += pkt['app_protocols'].get('Telnet', 0)
                smtp_count += pkt['app_protocols'].get('SMTP', 0)
                ssh_count += pkt['app_protocols'].get('SSH', 0)
                irc_count += pkt['app_protocols'].get('IRC', 0)
                dhcp_count += pkt['app_protocols'].get('DHCP', 0)
            
            # Count ARP packets
            if pkt.get('is_arp', False):
                arp_count += 1
                
            # Count LLC packets (layer 2)
            if pkt.get('is_llc', False):
                llc_count += 1
                
            # Count TCP flags
            if 'tcp_flags' in pkt:
                flags = pkt['tcp_flags']
                if flags.get('SYN', 0):
                    syn_count += 1
                if flags.get('ACK', 0):
                    ack_count += 1
                if flags.get('FIN', 0):
                    fin_count += 1
                if flags.get('RST', 0):
                    rst_count += 1
                if flags.get('PSH', 0):
                    psh_count += 1
                if flags.get('URG', 0):
                    urg_count += 1
                if flags.get('ECE', 0):
                    ece_count += 1
                if flags.get('CWR', 0):
                    cwr_count += 1
                    
            # Track inbound/outbound for Drate calculation
            if first_seen_src_ip is None:
                first_seen_src_ip = pkt.get('src_ip')
                first_seen_src_port = pkt.get('src_port')
                outbound_packets += 1
            else:
                if pkt.get('src_ip') == first_seen_src_ip and pkt.get('src_port') == first_seen_src_port:
                    outbound_packets += 1
                else:
                    inbound_packets += 1
        
        # Calculate all 33 features
        
        # 1. Protocol Type - Use most common protocol in the flow
        if tcp_count > udp_count and tcp_count > icmp_count:
            features[1] = 6  # TCP
        elif udp_count > tcp_count and udp_count > icmp_count:
            features[1] = 17  # UDP
        elif icmp_count > 0:
            features[1] = 1  # ICMP
        else:
            features[1] = 0  # Unknown
            
        # 2. Duration - TTL value (reuse from original implementation)
        ttls = [pkt.get('ttl', 0) for pkt in window if 'ttl' in pkt]
        features[2] = max(set(ttls), key=ttls.count) if ttls else 0
        
        # 3. Rate - Overall packet transmission rate
        duration = features[0]
        num_packets = len(window)
        features[3] = num_packets / duration if duration > 0 else 0
        
        # 4. Drate - Inbound packet transmission rate
        features[4] = inbound_packets / duration if duration > 0 else 0
        
        # 5-11. TCP Flag values (0 or 1 if flag is present in any packet)
        features[5] = 1 if fin_count > 0 else 0  # fin_flag_number
        features[6] = 1 if syn_count > 0 else 0  # syn_flag_number
        features[7] = 1 if rst_count > 0 else 0  # rst_flag_number
        features[8] = 1 if psh_count > 0 else 0  # psh_flag_number
        features[9] = 1 if ack_count > 0 else 0  # ack_flag_number
        features[10] = 1 if ece_count > 0 else 0  # ece_flag_number
        features[11] = 1 if cwr_count > 0 else 0  # cwr_flag_number
        
        # 12-15. Flag counts
        features[12] = ack_count  # ack_count
        features[13] = syn_count  # syn_count
        features[14] = fin_count  # fin_count
        features[15] = urg_count  # urg_count
        
        # 16-22. Application layer protocols
        features[16] = 1 if http_count > 0 else 0  # HTTP
        features[17] = 1 if https_count > 0 else 0  # HTTPS
        features[18] = 1 if dns_count > 0 else 0  # DNS
        features[19] = 1 if telnet_count > 0 else 0  # Telnet
        features[20] = 1 if smtp_count > 0 else 0  # SMTP
        features[21] = 1 if ssh_count > 0 else 0  # SSH
        features[22] = 1 if irc_count > 0 else 0  # IRC
        
        # 23-29. Network/Transport layer protocols
        features[23] = 1 if tcp_count > 0 else 0  # TCP
        features[24] = 1 if udp_count > 0 else 0  # UDP
        features[25] = 1 if dhcp_count > 0 else 0  # DHCP
        features[26] = 1 if arp_count > 0 else 0  # ARP
        features[27] = 1 if icmp_count > 0 else 0  # ICMP
        features[28] = 1 if ip_count > 0 else 0  # IPv
        features[29] = 1 if llc_count > 0 else 0  # LLC
        
        # 30. Tot_sum - Sum of packet sizes in flow
        features[30] = sum(packet_lengths)
        
        # 31. IAT - Mean inter-arrival time
        if len(timestamps) > 1:
            features[31] = np.mean(np.diff(timestamps))
        else:
            features[31] = 0
            
        # 32. Number - Number of packets in the flow
        features[32] = len(window)
        
        return features

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
        arp_pkt = pkt.get_protocol(arp.arp)
        icmp_pkt = pkt.get_protocol(icmp.icmp)

        # Extract source and destination ports
        src_port = tcp_pkt.src_port if tcp_pkt else (udp_pkt.src_port if udp_pkt else 0)
        dst_port = tcp_pkt.dst_port if tcp_pkt else (udp_pkt.dst_port if udp_pkt else 0)
        
        # Detect application layer protocols
        app_protocols = self.detect_application_protocol(pkt, src_port, dst_port)

        packet_data = {
            'time': time.time(),
            'length': len(pkt),
            'protocol': ip_pkt.proto if ip_pkt else 0,
            'ttl': ip_pkt.ttl if ip_pkt else 0,
            'header_length': self.calculate_header_length(pkt),
            'src_ip': ip_pkt.src if ip_pkt else None,
            'dst_ip': ip_pkt.dst if ip_pkt else None,
            'src_port': src_port,
            'dst_port': dst_port,
            'is_arp': 1 if arp_pkt else 0,
            'is_llc': 1 if eth.ethertype < 1500 else 0,  # LLC uses values below 1500
            'app_protocols': app_protocols
        }

        # Extract TCP flags if available
        if tcp_pkt:
            packet_data['tcp_flags'] = {
                'SYN': 1 if tcp_pkt.bits & 0x02 else 0,
                'ACK': 1 if tcp_pkt.bits & 0x10 else 0,
                'RST': 1 if tcp_pkt.bits & 0x04 else 0,
                'URG': 1 if tcp_pkt.bits & 0x20 else 0,
                'PSH': 1 if tcp_pkt.bits & 0x08 else 0,
                'FIN': 1 if tcp_pkt.bits & 0x01 else 0,
                'ECE': 1 if tcp_pkt.bits & 0x40 else 0,
                'CWR': 1 if tcp_pkt.bits & 0x80 else 0
            }

        # Store packet in flow window
        if flow_id not in self.flow_windows:
            self.flow_windows[flow_id] = []
        self.flow_windows[flow_id].append(packet_data)

        # Forward packet immediately (don't wait for analysis)
        self.forward_without_install(msg, datapath, in_port, eth, dst, src)

        # Process window when we have 20 packets
        if len(self.flow_windows[flow_id]) >= 20:
            try:
                # Extract aggregated features
                features = self.extract_window_features(flow_id)
                
                # Send prediction to ML model if connected
                if self.ml_connected:
                    try:
                        response = requests.post(
                            self.ml_api,
                            json={'features': features},
                            timeout=1.0
                        )
                        result = response.json()
                        is_attack = result.get('is_attack', False)
                        attack_type = result.get('attack_type', 0)
                        confidence = result.get('confidence', 0.0)

                        if is_attack:
                            self.logger.info("Attack detected! Type: {}, Confidence: {:.2f}".format(attack_type, confidence))
                            self.install_drop_rule(datapath, flow_id)
                        else:
                            self.logger.debug("Benign traffic. Confidence: {:.2f}".format(confidence))
                    except Exception as e:
                        self.logger.error("Error sending prediction request: {}".format(e))
                        is_attack = False
                        attack_type = 0
                        confidence = 0.0
                else:
                    # Default values when ML model is not connected
                    is_attack = False
                    attack_type = 0
                    confidence = 0.0
                    self.logger.debug("ML model not connected, skipping prediction")

                # Always send data to dashboard for both benign and attack traffic
                if self.ws_connected:
                    message = {
                        'timestamp': time.time() * 1000,
                        'features': features,
                        'flow_id': flow_id,
                        'packet_count': len(self.flow_windows[flow_id]),
                        'decision': 'BLOCK' if is_attack else 'ALLOW',
                        'attack_type': attack_type,
                        'confidence': confidence,
                        'flow_duration': features[0]
                    }
                    try:
                        self.ws.send(json.dumps(message))
                    except Exception as e:
                        self.logger.error("Failed to send to dashboard: {}".format(e))
                        self.ws_connected = False
                        # Try to reconnect
                        self.connect_dashboard()

            except Exception as e:
                self.logger.error("Error processing window: {}".format(e))
            finally:
                # Clear the window after processing
                self.flow_windows[flow_id] = []

    # Helper functions
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
            data=data        )
        datapath.send_msg(out)
        
    def install_drop_rule(self, datapath, flow_id):
        """Install drop rule for malicious flow"""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Extract flow info from flow_id
        try:
            # Parse flow_id based on format
            if flow_id.startswith("ICMP"):
                parts = flow_id.split("-")
                if len(parts) < 3:
                    self.logger.warning("Invalid ICMP flow_id format: {}".format(flow_id))
                    return
                    
                match = parser.OFPMatch(
                    eth_type=0x0800,  # IPv4
                    ipv4_src=parts[1],
                    ipv4_dst=parts[2],
                    ip_proto=1  # ICMP
                )
                
                # Store source and destination IPs for notification
                src_ip = parts[1]
                dst_ip = parts[2]
                protocol = "ICMP"
                src_port = dst_port = 0
                
            elif flow_id.startswith("PROTO"):
                parts = flow_id.split("-")
                if len(parts) < 3:
                    self.logger.warning("Invalid PROTO flow_id format: {}".format(flow_id))
                    return
                    
                match = parser.OFPMatch(
                    eth_type=0x0800,  # IPv4
                    ipv4_src=parts[2],
                    ipv4_dst=parts[3],
                    ip_proto=int(parts[0][5:])  # Extract protocol number
                )
                
                # Store source and destination IPs for notification
                src_ip = parts[2]
                dst_ip = parts[3]
                protocol = "Protocol-{}".format(parts[0][5:])
                src_port = dst_port = 0
                
            else:
                # Standard TCP/UDP flow
                parts = flow_id.split("-")
                if len(parts) < 3:
                    self.logger.warning("Invalid flow_id format: {}".format(flow_id))
                    return
                    
                src_parts = parts[0].split(":")
                dst_parts = parts[1].split(":")
                protocol_num = int(parts[2])
                
                match = parser.OFPMatch(
                    eth_type=0x0800,  # IPv4
                    ipv4_src=src_parts[0],
                    ipv4_dst=dst_parts[0],
                    ip_proto=protocol_num
                )
                
                # Store source and destination IPs for notification
                src_ip = src_parts[0]
                dst_ip = dst_parts[0]
                src_port = int(src_parts[1])
                dst_port = int(dst_parts[1])
                
                if protocol_num == 6:
                    protocol = "TCP"
                    # Add port information for TCP
                    match.append_field(ofproto_v1_3.OXM_OF_TCP_SRC, src_port)
                    match.append_field(ofproto_v1_3.OXM_OF_TCP_DST, dst_port)
                elif protocol_num == 17:
                    protocol = "UDP"
                    # Add port information for UDP
                    match.append_field(ofproto_v1_3.OXM_OF_UDP_SRC, src_port)
                    match.append_field(ofproto_v1_3.OXM_OF_UDP_DST, dst_port)
                else:
                    protocol = "Protocol-{}".format(protocol_num)

            # Add flow with drop action (empty actions list)
            self.add_flow(
                datapath, 
                priority=10, 
                match=match, 
                actions=[],  # No actions = drop
                idle_timeout=60, 
                hard_timeout=120
            )
            
            # Send blocking notification to dashboard
            if self.ws_connected:
                try:
                    block_message = {
                        'timestamp': time.time() * 1000,
                        'event_type': 'BLOCK_RULE_INSTALLED',
                        'flow_id': flow_id,
                        'src_ip': src_ip,
                        'dst_ip': dst_ip,
                        'src_port': src_port,
                        'dst_port': dst_port,
                        'protocol': protocol,
                        'message': "Malicious traffic blocked: {} -> {}".format(src_ip, dst_ip),
                        'duration': 60  # Timeout in seconds
                    }
                    self.ws.send(json.dumps(block_message))
                    self.logger.info("Block notification sent to dashboard for {}".format(flow_id))
                except Exception as e:
                    self.logger.error("Failed to send block notification to dashboard: {}".format(e))
                    # Try to reconnect if websocket connection failed
                    if "socket is already closed" in str(e) or "connection is already closed" in str(e):
                        self.ws_connected = False
                        self.connect_dashboard()
            
            self.logger.info("Installed drop rule for {}".format(flow_id))

        except Exception as e:
            self.logger.error("Error installing drop rule: {}".format(e))
