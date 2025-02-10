from scapy.all import rdpcap, Ether, IP, TCP, Raw
from collections import defaultdict

def extract_http_host(payload):
    """
    Extract the Host header from an HTTP request.

    :param payload: Raw packet payload.
    :return: Hostname (e.g., "youtube.com") or None if not found.
    """
    try:
        payload = payload.decode("utf-8", errors="ignore")
        for line in payload.split("\n"):
            if line.startswith("Host:"):
                return line.split(" ")[1].strip()
    except:
        pass
    return None

def extract_https_sni(payload):
    """
    Extract the SNI field from a TLS handshake.

    :param payload: Raw packet payload.
    :return: Server Name (e.g., "youtube.com") or None if not found.
    """
    try:
        if payload[0] == 0x16 and payload[5] == 0x01:  # TLS handshake
            payload = payload[5:]  # Skip TLS header
            if payload[0] == 0x01:  # Client Hello
                payload = payload[1:]  # Skip handshake type
                payload = payload[3:]  # Skip length
                payload = payload[2:]  # Skip version
                payload = payload[32:]  # Skip random
                session_id_length = payload[0]
                payload = payload[1 + session_id_length:]  # Skip session ID
                cipher_suites_length = int.from_bytes(payload[:2], byteorder="big")
                payload = payload[2 + cipher_suites_length:]  # Skip cipher suites
                compression_methods_length = payload[0]
                payload = payload[1 + compression_methods_length:]  # Skip compression methods
                extensions_length = int.from_bytes(payload[:2], byteorder="big")
                payload = payload[2:]
                while extensions_length > 0:
                    extension_type = int.from_bytes(payload[:2], byteorder="big")
                    extension_length = int.from_bytes(payload[2:4], byteorder="big")
                    payload = payload[4:]
                    if extension_type == 0:  # SNI extension
                        server_name_list_length = int.from_bytes(payload[:2], byteorder="big")
                        payload = payload[2:]
                        server_name_type = payload[0]
                        server_name_length = int.from_bytes(payload[1:3], byteorder="big")
                        payload = payload[3:]
                        return payload[:server_name_length].decode("utf-8", errors="ignore")
                    else:
                        payload = payload[extension_length:]
                    extensions_length -= 4 + extension_length
    except:
        pass
    return None
def analyze_traffic(pcap_file):
    """
    Analyze the captured packets and extract the general device level and application level metrics.

    :param pcap_file: Path to the .pcap file.
    :return: Dictionary containing traffic metrics.
    """
    # Read the .pcap file
    packets = rdpcap(pcap_file)

    # Initialize metrics
    metrics = {
        "total_packets": len(packets),
        "protocols": defaultdict(int),
        "source_ips": defaultdict(int),
        "destination_ips": defaultdict(int),
        "total_bytes": 0,
        "device_traffic":defaultdict(lambda: {"bytes_sent": 0, "bytes_received": 0}),
        "application_traffic": defaultdict(int),
    }
   
   # Domain to application mapping
    domain_to_app = {
        "youtube.com": "YouTube",
        "netflix.com": "Netflix",
        "zoom.us": "Zoom",
        "facebook.com": "Facebook",
        "google.com": "Google",
        # Add more mappings as needed
    }
   
    # Analyze each packet
    for packet in packets:
        if Ether in packet and IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            length = len(packet)

            # General metrics
            metrics["protocols"][packet[IP].proto] += 1
            metrics["source_ips"][src_ip] += 1
            metrics["destination_ips"][dst_ip] += 1
            metrics["total_bytes"] += length

            # Device-level metrics
            metrics["device_traffic"][src_ip]["bytes_sent"] += length
            metrics["device_traffic"][dst_ip]["bytes_received"] += length

           # Application-level metrics (for HTTP/HTTPS traffic)
            if TCP in packet:
                payload = bytes(packet[TCP].payload)
                if packet[TCP].dport == 80:  # HTTP
                    host = extract_http_host(payload)
                    if host:
                        app = domain_to_app.get(host, host)
                        metrics["application_traffic"][app] += length
                elif packet[TCP].dport == 443:  # HTTPS
                    sni = extract_https_sni(payload)
                    if sni:
                        app = domain_to_app.get(sni, sni)
                        metrics["application_traffic"][app] += length


    # Convert protocol numbers to names
    protocol_names = {6: "TCP", 17: "UDP"}
    metrics["protocols"] = {protocol_names.get(k, k): v for k, v in metrics["protocols"].items()}

    return metrics