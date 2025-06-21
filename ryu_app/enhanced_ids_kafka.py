# Enhanced IDS Controller with Kafka Integration
# Compatible with Python 2.7

import time
import json
import os
import threading
from collections import defaultdict
import numpy as np

# Ryu imports
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, tcp, udp, ether_types
from ryu.lib.packet import arp, dhcp, icmp

# Kafka imports - using kafka-python for Python 2.7 compatibility
try:
    from kafka import KafkaProducer, KafkaConsumer
    print("Kafka-python library imported successfully")
    KAFKA_AVAILABLE = True
except ImportError:
    KAFKA_AVAILABLE = False
    print("Warning: kafka-python not available. Install with: pip install kafka-python")

# WebSocket import
try:
    import websocket
    WS_AVAILABLE = True
except ImportError:
    WS_AVAILABLE = False
    print("Warning: websocket-client not available.")


class EnhancedIDSControllerKafka(app_manager.RyuApp):
    """
    Enhanced IDS Controller with Kafka integration for asynchronous processing.
    
    Features:
    - Extracts features from 100-packet windows
    - Sends features to Kafka 'features' topic
    - Optionally consumes decisions from Kafka 'decisions' topic
    - Maintains WebSocket connection to dashboard
    """
    
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(EnhancedIDSControllerKafka, self).__init__(*args, **kwargs)
        
        # Network state
        self.flow_stats = defaultdict(dict)
        self.mac_to_port = {}
        self.flow_windows = defaultdict(list)  # Store packets per flow
        
        # Configuration from environment variables with defaults
        self.kafka_bootstrap_servers = os.getenv('KAFKA_BOOTSTRAP_SERVERS', 'kafka:9092')
        self.features_topic = os.getenv('FEATURES_TOPIC', 'features')
        self.decisions_topic = os.getenv('DECISIONS_TOPIC', 'decisions')
        self.window_size = int(os.getenv('WINDOW_SIZE', '100'))  # Number of packets per window
        
        # Dashboard configuration
        self.ws_url = os.getenv('DASHBOARD_WS_URL', 'ws://dashboard:8080/ws')
        self.ws = None
        self.ws_connected = False
        
        # Kafka components
        self.kafka_producer = None
        self.kafka_consumer = None
        self.kafka_connected = False
    
        # Feature names for reference (33 features)
        self.feature_names = [
            'flow_duration', 'Protocol_Type', 'Duration', 'Rate', 'Drate',
            'fin_flag_number', 'syn_flag_number', 'rst_flag_number', 'psh_flag_number',
            'ack_flag_number', 'ece_flag_number', 'cwr_flag_number', 'ack_count',
            'syn_count', 'fin_count', 'urg_count', 'HTTP', 'HTTPS', 'DNS',
            'Telnet', 'SMTP', 'SSH', 'IRC', 'TCP', 'UDP', 'DHCP', 'ARP',
            'ICMP', 'IPv', 'LLC', 'Tot_sum', 'IAT', 'Number'
        ]
        
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
        
        # Initialize services with delay - BUT DON'T BLOCK THE MAIN THREAD
        self.logger.info("Starting Enhanced IDS Controller with Kafka integration...")
        
        # Start Kafka initialization in background thread
        self._start_kafka_initialization_thread()
        
        self.logger.info("Enhanced IDS Controller with Kafka initialized successfully (Kafka connecting in background)")

    def _start_kafka_initialization_thread(self):
        """Start Kafka initialization in a separate thread to avoid blocking OpenFlow"""
        def kafka_init_worker():
            """Background thread for Kafka initialization"""
            self.logger.info("Starting Kafka initialization in background thread...")
            
            # Wait a bit for other services to start
            time.sleep(5)
            
            # Initialize Kafka producer
            self._init_kafka_producer_async()
            
            # Initialize Kafka consumer
            self._init_kafka_consumer()
            
            # Connect to dashboard
            self._connect_dashboard()
            
            # Start decision consumer if available
            if self.kafka_consumer:
                self._start_decision_consumer_thread()
                
            self.logger.info("Background Kafka initialization completed")
        
        # Start the thread
        kafka_thread = threading.Thread(target=kafka_init_worker)
        kafka_thread.daemon = True
        kafka_thread.start()

    def _init_kafka_producer_async(self):
        """Initialize Kafka producer without blocking the main thread - Python 2.7 compatible"""
        if not KAFKA_AVAILABLE:
            self.logger.error("Kafka not available - features will not be sent to Kafka")
            return
            
        max_retries = 10
        retry_delay = 5
        
        self.logger.info("Attempting to connect to Kafka using bootstrap servers: {0}".format(
            self.kafka_bootstrap_servers))
        
        for attempt in range(max_retries):
            try:
                self.logger.info("Attempting to connect to Kafka (attempt {0}/{1})...".format(attempt + 1, max_retries))
                
                # Configure producer - Python 2.7 compatible settings
                producer_config = {
                    'bootstrap_servers': [self.kafka_bootstrap_servers],
                    'value_serializer': lambda x: json.dumps(x).encode('utf-8'),
                    'key_serializer': lambda x: x.encode('utf-8') if x else None,
                    # Configuration for reliability
                    'acks': 'all',
                    'retries': 5,
                    'max_in_flight_requests_per_connection': 1,
                    # Reduced timeout settings to avoid long blocks
                    'request_timeout_ms': 10000,  # 10 seconds instead of 60
                    'retry_backoff_ms': 100,
                    # Buffer settings
                    'batch_size': 16384,
                    'linger_ms': 10,
                    'buffer_memory': 33554432,
                    'max_request_size': 1048576,
                    'connections_max_idle_ms': 600000,
                    'api_version': (0, 10, 1)
                }                
                self.kafka_producer = KafkaProducer(**producer_config)
                
                # Test connection with shorter timeout
                try:
                    test_value = {'test': 'connection', 'timestamp': time.time()}
                    test_key = 'test_connection_{0}'.format(int(time.time()))
                    
                    # Send test message - use a shorter timeout
                    future = self.kafka_producer.send(self.features_topic, key=test_key, value=test_value)
                    record_metadata = future.get(timeout=5)  # Reduced from 30 to 5 seconds
                    
                    self.logger.info("Kafka test message sent successfully to topic {0} partition {1} offset {2}".format(
                        record_metadata.topic, record_metadata.partition, record_metadata.offset))
                    
                    # Quick flush with short timeout
                    self.kafka_producer.flush(timeout=5)
                    
                except Exception as e:
                    self.logger.warning("Test message send failed: {0}".format(str(e)))
                    raise e
                
                self.kafka_connected = True
                self.logger.info("Kafka producer initialized successfully")
                return
                
            except Exception as e:
                self.logger.warning("Kafka connection attempt {0} failed: {1}".format(attempt + 1, str(e)))
                
                # Clean up failed producer
                if hasattr(self, 'kafka_producer') and self.kafka_producer:
                    try:
                        self.kafka_producer.close(timeout=1)  # Short timeout
                    except Exception:
                        pass
                    self.kafka_producer = None
                
                if attempt < max_retries - 1:
                    self.logger.info("Retrying in {0} seconds...".format(retry_delay))
                    time.sleep(retry_delay)
                    retry_delay = min(retry_delay * 2, 30)
        
        self.logger.error("Failed to connect to Kafka after {0} attempts".format(max_retries))
        self.kafka_connected = False
        self.kafka_producer = None

    def _init_kafka_consumer(self):
        """Initialize Kafka consumer for receiving decisions (optional) - Python 2.7 compatible"""
        if not KAFKA_AVAILABLE:
            return
        
        # Log the bootstrap servers for debugging
        self.logger.info("Initializing Kafka consumer for topic '{0}' using bootstrap servers: {1}".format(
            self.decisions_topic, self.kafka_bootstrap_servers))
            
        try:
            consumer_config = {
                'bootstrap_servers': [self.kafka_bootstrap_servers],
                'group_id': 'ryu-decision-consumer',
                'value_deserializer': lambda x: json.loads(x.decode('utf-8')),
                'key_deserializer': lambda x: x.decode('utf-8') if x else None,
                # Start from the latest messages
                'auto_offset_reset': 'latest',
                'enable_auto_commit': True,
                # Python 2.7 compatible settings
                'consumer_timeout_ms': 1000,
                'fetch_max_wait_ms': 500
            }
            
            self.kafka_consumer = KafkaConsumer(self.decisions_topic, **consumer_config)
            self.logger.info("Kafka consumer for decisions initialized successfully")
        except Exception as e:
            self.logger.error("Failed to initialize Kafka consumer: {0}".format(str(e)))
            self.kafka_consumer = None

    def _send_features_to_kafka(self, flow_id, features):
        """Send extracted features to Kafka features topic - Python 2.7 compatible non-blocking version"""
        # Lazy initialization - try to connect if not connected
        if not self.kafka_connected and KAFKA_AVAILABLE:
            self._try_quick_kafka_connect()
        
        if not self.kafka_connected or not self.kafka_producer:
            self.logger.warning("Kafka not available - skipping feature transmission")
            return False
            
        try:
            # Create feature payload
            feature_payload = {
                'flow_id': flow_id,
                'timestamp': time.time(),
                'features': features,
                'window_size': self.window_size
            }
             # Send to Kafka asynchronously - Python 2.7 doesn't have add_callback
            # So we'll use a different approach
            future = self.kafka_producer.send(
                self.features_topic,
                key=flow_id,
                value=feature_payload
            )
            
            # Start a background thread to handle the result
            def handle_send_result():
                try:
                    record_metadata = future.get(timeout=5)
                    self.logger.debug("Features sent to Kafka for flow: {0} (partition: {1}, offset: {2})".format(
                        flow_id, record_metadata.partition, record_metadata.offset))
                except Exception as e:
                    self.logger.error("Failed to send features to Kafka for flow {0}: {1}".format(flow_id, str(e)))
                    # Mark as disconnected for reconnection attempt
                    self.kafka_connected = False
            
            # Start result handler in background thread
            result_thread = threading.Thread(target=handle_send_result)
            result_thread.daemon = True
            result_thread.start()
            
            return True  # Return immediately
            
        except Exception as e:
            self.logger.error("Failed to send features to Kafka: {0}".format(str(e)))
            self.kafka_connected = False
            return False

    def _try_quick_kafka_connect(self):
        """Quick, non-blocking Kafka connection attempt - Python 2.7 compatible"""
        if self.kafka_connected or not KAFKA_AVAILABLE:
            return
        
        try:
            self.logger.info("Attempting quick Kafka connection...")
            
            quick_config = {
                'bootstrap_servers': [self.kafka_bootstrap_servers],
                'value_serializer': lambda x: json.dumps(x).encode('utf-8'),
                'key_serializer': lambda x: x.encode('utf-8') if x else None,
                'acks': 1,  # Reduced from 'all' for faster response
                'retries': 1,  # Reduced retries
                'request_timeout_ms': 5000,  # Short timeout
                'api_version': (0, 10, 1)
            }
            
            self.kafka_producer = KafkaProducer(**quick_config)
            
            self.kafka_connected = True
            self.logger.info("Quick Kafka connection successful")
            
        except Exception as e:
            self.logger.warning("Quick Kafka connection failed: {0}".format(str(e)))
            self.kafka_connected = False
            self.kafka_producer = None

    def _start_decision_consumer_thread(self):
        """Start background thread to consume decisions from Kafka - Python 2.7 compatible"""
        def consume_decisions():
            """Background thread function to consume decisions"""
            self.logger.info("Starting decision consumer thread")
            while True:
                try:
                    if self.kafka_consumer:
                        # Poll for messages with timeout
                        messages = self.kafka_consumer.poll(timeout_ms=1000)
                        
                        # Python 2.7 compatible iteration
                        for topic_partition in messages:
                            msgs = messages[topic_partition]
                            for message in msgs:
                                self._handle_decision_message(message.value)
                                
                    time.sleep(0.1)  # Small delay to prevent high CPU usage
                except Exception as e:
                    self.logger.error("Error in decision consumer: {0}".format(str(e)))
                    time.sleep(1)  # Wait before retrying
        
        # Start the thread
        consumer_thread = threading.Thread(target=consume_decisions)
        consumer_thread.daemon = True
        consumer_thread.start()

    def _handle_decision_message(self, decision):
        """Handle incoming decision from Kafka - Python 2.7 compatible"""
        try:
            flow_id = decision.get('flow_id', '')
            is_attack = decision.get('is_attack', False)
            attack_type = decision.get('attack_type', 0)
            confidence = decision.get('confidence', 0.0)
            
            self.logger.info("Received decision for flow {0}: {1} (confidence: {2:.2f})".format(
                flow_id, "ATTACK" if is_attack else "BENIGN", confidence))
            
            # If it's an attack, install drop rule
            if is_attack:
                self.logger.info("Installing drop rule for malicious flow: {0}".format(flow_id))
                # Note: We would need the datapath reference to install the rule
                # This could be enhanced by maintaining a mapping of flow_id to datapath
                
            # Forward decision to dashboard
            if self.ws_connected:
                dashboard_message = {
                    'timestamp': time.time() * 1000,
                    'flow_id': flow_id,
                    'decision': 'BLOCK' if is_attack else 'ALLOW',
                    'attack_type': attack_type,
                    'confidence': confidence,
                    'source': 'kafka'
                }
                try:
                    self.ws.send(json.dumps(dashboard_message))
                except Exception as e:
                    self.logger.error("Failed to send decision to dashboard: {0}".format(str(e)))
                    self.ws_connected = False
                    self._connect_dashboard()
                    
        except Exception as e:
            self.logger.error("Error handling decision message: {0}".format(str(e)))

    def _connect_dashboard(self):
        """Connect to the dashboard WebSocket - Python 2.7 compatible"""
        if not WS_AVAILABLE:
            self.logger.warning("WebSocket client not available - dashboard connection disabled")
            return
            
        try:
            self.ws = websocket.WebSocket()
            self.ws.connect(self.ws_url)
            self.ws_connected = True
            self.logger.info("Connected to dashboard WebSocket")
        except Exception as e:
            self.logger.error("Failed to connect to dashboard WebSocket: {0}".format(e))
            self.ws_connected = False

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
        
        # Check if packet contains DHCP
        if pkt.get_protocol(dhcp.dhcp):
            protocols['DHCP'] = 1
            
        # DNS detection based on port
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

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """Handle switch features event"""
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

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        """
        Main packet processing handler with Kafka integration.
        
        Process:
        1. Extract packet information and store in window
        2. When window reaches 100 packets, extract features
        3. Send features to Kafka 'features' topic asynchronously
        4. Clear window and continue processing
        """
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

        # Process window when we have 100 packets
        if len(self.flow_windows[flow_id]) >= self.window_size:
            try:
                # Extract aggregated features
                features = self.extract_window_features(flow_id)
                
                # Send features to Kafka asynchronously (non-blocking)
                kafka_sent = self._send_features_to_kafka(flow_id, features)
                
                if kafka_sent:
                    self.logger.debug("Features for flow {0} sent to Kafka successfully".format(flow_id))
                else:
                    self.logger.warning("Failed to send features to Kafka for flow {0}".format(flow_id))
                
                # Optional: Send summary to dashboard for monitoring
                if self.ws_connected:
                    summary_message = {
                        'timestamp': time.time() * 1000,
                        'flow_id': flow_id,
                        'packet_count': len(self.flow_windows[flow_id]),
                        'flow_duration': features[0],
                        'status': 'features_sent_to_kafka' if kafka_sent else 'kafka_send_failed',
                        'source': 'ryu_controller'
                    }
                    try:
                        self.ws.send(json.dumps(summary_message))
                    except Exception as e:
                        self.logger.error("Failed to send summary to dashboard: {0}".format(str(e)))
                        self.ws_connected = False
                        self._connect_dashboard()

            except Exception as e:
                self.logger.error("Error processing window for flow {0}: {1}".format(flow_id, str(e)))
            finally:
                # Clear the window after processing
                self.flow_windows[flow_id] = []
                self.logger.debug("Window cleared for flow {0}".format(flow_id))

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

    def close(self):
        """Clean up resources on controller shutdown"""
        if self.kafka_producer:
            try:
                self.kafka_producer.flush(timeout=30)
                self.kafka_producer.close(timeout=10)
                self.logger.info("Kafka producer closed")
            except Exception as e:
                self.logger.error("Error closing Kafka producer: {0}".format(str(e)))
                
        if self.kafka_consumer:
            try:
                self.kafka_consumer.close()
                self.logger.info("Kafka consumer closed")
            except Exception as e:
                self.logger.error("Error closing Kafka consumer: {0}".format(str(e)))
                
        if self.ws and self.ws_connected:
            try:
                self.ws.close()
                self.logger.info("WebSocket connection closed")
            except Exception as e:
                self.logger.error("Error closing WebSocket: {0}".format(str(e)))

