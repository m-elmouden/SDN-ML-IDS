# Enhanced IDS Controller with RabbitMQ Integration - 15 Features Version
# Compatible with Python 2.7

import time
import json
import os
import threading
from collections import defaultdict

# Ryu imports
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, tcp, udp, ether_types
from ryu.lib.packet import arp, dhcp, icmp

# RabbitMQ imports - using pika for Python 2.7 compatibility
try:
    import pika
    print("Pika library imported successfully")
    RABBITMQ_AVAILABLE = True
except ImportError:
    RABBITMQ_AVAILABLE = False
    print("Warning: pika not available. Install with: pip install pika")

# WebSocket import
try:
    import websocket
    WS_AVAILABLE = True
except ImportError:
    WS_AVAILABLE = False
    print("Warning: websocket-client not available.")


class EnhancedIDSController15RabbitMQ(app_manager.RyuApp):
    """
    Enhanced IDS Controller with RabbitMQ integration for asynchronous processing - 15 Features Version.
    
    Features:
    - Extracts 15 features from 100-packet windows
    - Sends features to RabbitMQ 'features' queue
    - Optionally consumes decisions from RabbitMQ 'decisions' queue
    - Maintains WebSocket connection to dashboard
    """
    
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(EnhancedIDSController15RabbitMQ, self).__init__(*args, **kwargs)
        
        # Network state
        self.flow_stats = defaultdict(dict)
        self.mac_to_port = {}
        self.flow_windows = defaultdict(list)  # Store packets per flow
        
        # Configuration from environment variables with defaults
        self.rabbitmq_url = os.getenv('RABBITMQ_URL', 'amqp://guest:guest@rabbitmq:5672/')
        self.features_queue = os.getenv('FEATURES_QUEUE', 'features')
        self.decisions_queue = os.getenv('DECISIONS_QUEUE', 'decisions')
        self.window_size = int(os.getenv('WINDOW_SIZE', '100'))  # Number of packets per window
        
        # Dashboard configuration
        self.ws_url = os.getenv('DASHBOARD_WS_URL', 'ws://dashboard:8080/ws')
        self.ws = None
        self.ws_connected = False
        
        # RabbitMQ components
        self.rabbitmq_connection = None
        self.producer_channel = None
        self.consumer_channel = None
        self.rabbitmq_connected = False        # Feature names for reference (15 features)
        self.feature_names = [
            'fin_flag_number', 'psh_flag_number', 'UDP', 'syn_flag_number', 'HTTP',
            'ICMP', 'Tot_sum', 'IAT', 'rst_count', 'Weight',
            'rst_flag_number', 'flow_duration', 'TCP', 'Rate', 'ARP'
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
        self.logger.info("Starting Enhanced IDS Controller (15 Features) with RabbitMQ integration...")
        
        # Start RabbitMQ initialization in background thread
        self._start_rabbitmq_initialization_thread()
        
        self.logger.info("Enhanced IDS Controller (15 Features) with RabbitMQ initialized successfully (RabbitMQ connecting in background)")

    def _start_rabbitmq_initialization_thread(self):
        """Start RabbitMQ initialization in a separate thread to avoid blocking OpenFlow"""
        def rabbitmq_init_worker():
            """Background thread for RabbitMQ initialization"""
            self.logger.info("Starting RabbitMQ initialization in background thread...")
            
            # Wait a bit for other services to start
            time.sleep(5)
            
            # Initialize RabbitMQ connection
            self._init_rabbitmq_connection()
            
            # Connect to dashboard
            self._connect_dashboard()
            
            # Start decision consumer if available
            if self.rabbitmq_connected:
                self._start_decision_consumer_thread()
                
            self.logger.info("Background RabbitMQ initialization completed")
        
        # Start the thread
        rabbitmq_thread = threading.Thread(target=rabbitmq_init_worker)
        rabbitmq_thread.daemon = True
        rabbitmq_thread.start()

    def _init_rabbitmq_connection(self):
        """Initialize RabbitMQ connection and channels - Python 2.7 compatible"""
        if not RABBITMQ_AVAILABLE:
            self.logger.error("RabbitMQ (pika) not available - features will not be sent to RabbitMQ")
            return
            
        max_retries = 10
        retry_delay = 5
        
        self.logger.info("Attempting to connect to RabbitMQ using URL: {0}".format(self.rabbitmq_url))
        
        for attempt in range(max_retries):
            try:
                self.logger.info("Attempting to connect to RabbitMQ (attempt {0}/{1})...".format(attempt + 1, max_retries))
                
                # Parse RabbitMQ URL and create connection parameters
                parameters = pika.URLParameters(self.rabbitmq_url)
                parameters.socket_timeout = 10
                parameters.connection_attempts = 3
                parameters.retry_delay = 2
                
                # Create blocking connection
                self.rabbitmq_connection = pika.BlockingConnection(parameters)
                
                # Create producer channel
                self.producer_channel = self.rabbitmq_connection.channel()
                
                # Declare queues (idempotent)
                self.producer_channel.queue_declare(queue=self.features_queue, durable=True)
                self.producer_channel.queue_declare(queue=self.decisions_queue, durable=True)
                
                # Test the connection
                self.producer_channel.basic_publish(
                    exchange='',
                    routing_key=self.features_queue,
                    body=json.dumps({
                        'test': 'connection',
                        'timestamp': time.time()
                    }),
                    properties=pika.BasicProperties(
                        delivery_mode=2,  # Make message persistent
                        content_type='application/json'
                    )
                )
                
                self.rabbitmq_connected = True
                self.logger.info("RabbitMQ connection initialized successfully")
                return
                
            except Exception as e:
                self.logger.warning("RabbitMQ connection attempt {0} failed: {1}".format(attempt + 1, str(e)))
                
                # Clean up failed connection
                if self.rabbitmq_connection and not self.rabbitmq_connection.is_closed:
                    try:
                        self.rabbitmq_connection.close()
                    except:
                        pass
                self.rabbitmq_connection = None
                self.producer_channel = None
                
                if attempt < max_retries - 1:
                    self.logger.info("Retrying in {0} seconds...".format(retry_delay))
                    time.sleep(retry_delay)
                    retry_delay = min(retry_delay * 2, 30)  # Exponential backoff capped at 30 seconds
        
        self.logger.error("Failed to connect to RabbitMQ after {0} attempts".format(max_retries))
        self.rabbitmq_connected = False

    def _send_features_to_rabbitmq(self, flow_id, features):
        """Send extracted features to RabbitMQ features queue"""
        if not self.rabbitmq_connected or not self.producer_channel:
            self.logger.warning("RabbitMQ not available - skipping feature transmission")
            return False
            
        try:
            # Create feature payload
            feature_payload = {
                'flow_id': flow_id,
                'timestamp': time.time(),
                'features': features,
                'window_size': self.window_size,
                'feature_count': 15
            }
            
            # Send to RabbitMQ features queue
            self.producer_channel.basic_publish(
                exchange='',
                routing_key=self.features_queue,
                body=json.dumps(feature_payload),
                properties=pika.BasicProperties(
                    delivery_mode=2,  # Make message persistent
                    content_type='application/json',
                    message_id=flow_id
                )
            )
            
            self.logger.debug("15 Features sent to RabbitMQ for flow: {0}".format(flow_id))
            return True
            
        except Exception as e:
            self.logger.error("Failed to send features to RabbitMQ: {0}".format(str(e)))
            
            # Connection might be broken - attempt to reconnect
            self.logger.info("Attempting to reconnect to RabbitMQ...")
            self.rabbitmq_connected = False
            self._init_rabbitmq_connection()
            
            return False

    def _start_decision_consumer_thread(self):
        """Start background thread to consume decisions from RabbitMQ"""
        def consume_decisions():
            self.logger.info("Starting non-blocking decision consumer thread")

            try:
                parameters = pika.URLParameters(self.rabbitmq_url)
                consumer_connection = pika.BlockingConnection(parameters)
                self.consumer_channel = consumer_connection.channel()
                self.consumer_channel.queue_declare(queue=self.decisions_queue, durable=True)
    
                self.logger.info("Decision consumer polling started...")
    
                while True:
                    try:
                        method_frame, properties, body = self.consumer_channel.basic_get(queue=self.decisions_queue, auto_ack=False)
                        if method_frame:
                            try:
                                decision = json.loads(body)
                                self._handle_decision_message(decision)
                                self.consumer_channel.basic_ack(method_frame.delivery_tag)
                            except Exception as e:
                                self.logger.error("Error processing decision: {}".format(e))
                                self.consumer_channel.basic_nack(method_frame.delivery_tag, requeue=False)
                        else:
                            time.sleep(0.5)  # Idle wait
                    except Exception as e:
                        self.logger.error("Polling error: {}".format(e))
                        time.sleep(1)
            except Exception as e:
                self.logger.error("Error initializing decision consumer: {}".format(e))

        # Start the thread
        consumer_thread = threading.Thread(target=consume_decisions)
        consumer_thread.daemon = True
        consumer_thread.start()

    def _handle_decision_message(self, decision):
        """Handle incoming decision from RabbitMQ"""
        try:
            flow_id = decision.get('flow_id', '')
            is_attack = decision.get('is_attack', False)
            attack_type = decision.get('attack_type', 0)
            confidence = decision.get('confidence', 0.0)
            
            self.logger.info("Received decision for flow {0}: {1} (confidence: {2:.2f})".format(
                flow_id, "ATTACK" if is_attack else "BENIGN", confidence))
            
            # If it's an attack, log for now (could install drop rule with datapath reference)
            if is_attack:
                self.logger.info("Malicious flow detected: {0}".format(flow_id))
                
            # Forward decision to dashboard
            if self.ws_connected:
                dashboard_message = {
                    'timestamp': time.time() * 1000,
                    'flow_id': flow_id,
                    'decision': 'BLOCK' if is_attack else 'ALLOW',
                    'attack_type': attack_type,
                    'confidence': confidence,
                    'source': 'rabbitmq'
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
        """Connect to the dashboard WebSocket"""
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



    def get_flow_id_2(self, pkt):
        """
        Generate a flow identifier based on IPs and protocol, grouping all packets between two hosts.
        Falls back to protocol-only for non-IP traffic.
        """
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if not ip_pkt:
            # Non-IPv4 traffic: use timestamp to distinguish
            return "NONIP-{}".format(int(time.time() * 1000))

        src_ip = ip_pkt.src
        dst_ip = ip_pkt.dst
        proto = ip_pkt.proto

        # Order IPs lexicographically for bidirectional grouping
        ip_pair = (src_ip, dst_ip) if src_ip < dst_ip else (dst_ip, src_ip)

        # Base flow key: IP pair + protocol
        flow_key = "{}-{}-{}".format(ip_pair[0], ip_pair[1], proto)

        # Optionally include ports for finer granularity
        # Uncomment to include port numbers:
        # port_proto = pkt.get_protocol(tcp.tcp) or pkt.get_protocol(udp.udp)
        # if port_proto:
        #     sport = port_proto.src_port
        #     dport = port_proto.dst_port
        #     flow_key = "{}:{}-{}:{}-{}".format(ip_pair[0], sport, ip_pair[1], dport, proto)

        return flow_key       

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
        """Calculate selected 15 flow features for a window of packets"""
        window = self.flow_windows[flow_id]
        if not window:
            return [0.0] * 15
            
        # Initialize feature vector with 15 features
        features = [0.0] * 15
        
        # Get timestamps for time-based calculations
        timestamps = [pkt['time'] for pkt in window]
        
        # Protocol counters
        tcp_count = udp_count = icmp_count = arp_count = 0
        http_count = 0
        
        # Flag counters
        syn_count = ack_count = fin_count = rst_count = 0
        psh_count = 0
        
        # Packet length statistics for total sum
        packet_lengths = []
        
        # Direction tracking for weight calculation
        first_packet_src_ip = None
        incoming_packets = 0
        outgoing_packets = 0
        
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
                
            # Extract packet lengths
            packet_lengths.append(pkt['length'])
                
            # Get application protocols
            if 'app_protocols' in pkt:
                http_count += pkt['app_protocols'].get('HTTP', 0)
            
            # Count ARP packets
            if pkt.get('is_arp', False):
                arp_count += 1
                
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
            
            # Track packet direction for weight calculation
            src_ip = pkt.get('src_ip')
            if src_ip:
                if first_packet_src_ip is None:
                    first_packet_src_ip = src_ip
                    outgoing_packets += 1
                elif src_ip == first_packet_src_ip:
                    outgoing_packets += 1
                else:
                    incoming_packets += 1
        
        # Calculate 15 features according to the specified order:
        # ['fin_flag_number', 'psh_flag_number', 'UDP', 'syn_flag_number', 'HTTP',
        #  'ICMP', 'Tot_sum', 'IAT', 'rst_count', 'Weight',
        #  'rst_flag_number', 'flow_duration', 'TCP', 'Rate', 'ARP']
        
        # 0. fin_flag_number - 1 if FIN flag present in any packet
        features[0] = 1 if fin_count > 0 else 0
        
        # 1. psh_flag_number - 1 if PSH flag present in any packet
        features[1] = 1 if psh_count > 0 else 0
        
        # 2. UDP - 1 if UDP packets present
        features[2] = 1 if udp_count > 0 else 0
        
        # 3. syn_flag_number - 1 if SYN flag present in any packet
        features[3] = 1 if syn_count > 0 else 0
        
        # 4. HTTP - 1 if HTTP packets present
        features[4] = 1 if http_count > 0 else 0
        
        # 5. ICMP - 1 if ICMP packets present
        features[5] = 1 if icmp_count > 0 else 0
        
        # 6. Tot_sum - Sum of packet sizes in flow
        features[6] = sum(packet_lengths)
          # 7. IAT - Mean inter-arrival time
        if len(timestamps) > 1:
            time_diffs = []
            for i in range(1, len(timestamps)):
                time_diffs.append(timestamps[i] - timestamps[i-1])
            features[7] = sum(time_diffs) / len(time_diffs)
        else:
            features[7] = 0
        
        # 8. rst_count - Count of RST flags
        features[8] = rst_count
        
        # 9. Weight - Product of incoming and outgoing packets
        features[9] = incoming_packets * outgoing_packets
        
        # 10. rst_flag_number - 1 if RST flag present in any packet
        features[10] = 1 if rst_count > 0 else 0
        
        # 11. flow_duration - Time between first and last packet
        features[11] = timestamps[-1] - timestamps[0] if len(timestamps) > 1 else 0
        
        # 12. TCP - 1 if TCP packets present
        features[12] = 1 if tcp_count > 0 else 0
        
        # 13. Rate - Overall packet transmission rate
        duration = features[11]  # Use the calculated flow_duration
        num_packets = len(window)
        features[13] = num_packets / duration if duration > 0 else 0
        
        # 14. ARP - 1 if ARP packets present
        features[14] = 1 if arp_count > 0 else 0
        
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
        Main packet processing handler with RabbitMQ integration.
        
        Process:
        1. Extract packet information and store in window
        2. When window reaches 100 packets, extract features
        3. Send 15 features to RabbitMQ 'features' queue
        4. Clear window and continue processing
        """
        msg = ev.msg
        datapath = msg.datapath
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        # Ignore LLDP and IPv6 packets
        if eth.ethertype in (ether_types.ETH_TYPE_LLDP, ether_types.ETH_TYPE_IPV6):
            return

        dst = eth.dst
        src = eth.src
        dpid = datapath.id

        # Learn MAC address
        if dpid not in self.mac_to_port:
            self.mac_to_port[dpid] = {}
        self.mac_to_port[dpid][src] = in_port

        # Get consistent flow ID
        flow_id = self.get_flow_id_2(pkt)

        # Parse packet for window storage
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        udp_pkt = pkt.get_protocol(udp.udp)
        arp_pkt = pkt.get_protocol(arp.arp)

        flags = tcp_pkt.bits if tcp_pkt else None
        if flags is not None:
           flags_str = "0x%02x" % flags
        else:
           flags_str = "None"

        self.logger.info(
             "PacketIn dpid=%s in_port=%s len=%d flags=%s",
              msg.datapath.id,
              msg.match['in_port'],
              len(msg.data),
              flags_str
              )


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

        # Process window when we have required number of packets
        L = len(self.flow_windows[flow_id])
        self.logger.info("Flow %s window size = %d", flow_id, L)
        if len(self.flow_windows[flow_id]) >= self.window_size:
            try:
                # Extract aggregated features (15 features)
                features = self.extract_window_features(flow_id)
                
                # Send features to RabbitMQ
                rabbitmq_sent = self._send_features_to_rabbitmq(flow_id, features)
                
                if rabbitmq_sent:
                    self.logger.debug("15 Features for flow {0} sent to RabbitMQ successfully".format(flow_id))
                else:
                    self.logger.warning("Failed to send 15 features to RabbitMQ for flow {0}".format(flow_id))
                
                # Optional: Send summary to dashboard for monitoring
                if self.ws_connected:
                    summary_message = {
                        'timestamp': time.time() * 1000,
                        'flow_id': flow_id,
                        'packet_count': len(self.flow_windows[flow_id]),
                        'feature_count': 15,
                        'status': 'features_sent_to_rabbitmq' if rabbitmq_sent else 'rabbitmq_send_failed',
                        'source': 'ryu_controller_15_features'
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
        if self.rabbitmq_connection and not self.rabbitmq_connection.is_closed:
            try:
                self.rabbitmq_connection.close()
                self.logger.info("RabbitMQ connection closed")
            except Exception as e:
                self.logger.error("Error closing RabbitMQ connection: {0}".format(str(e)))
                
        if self.ws and self.ws_connected:
            try:
                self.ws.close()
                self.logger.info("WebSocket connection closed")
            except Exception as e:
                self.logger.error("Error closing WebSocket: {0}".format(str(e)))
