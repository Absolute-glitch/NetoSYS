from scapy.all import rdpcap
from collections import defaultdict

def analyze_traffic(pcap_file):
    """
    Analyze the captured packets and extract metrics.

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
    }

    # Analyze each packet
    for packet in packets:
        # Count protocols (e.g., TCP, UDP)
        if "IP" in packet:
            metrics["protocols"][packet["IP"].proto] += 1

            # Count source and destination IPs
            metrics["source_ips"][packet["IP"].src] += 1
            metrics["destination_ips"][packet["IP"].dst] += 1

            # Calculate total bytes
            metrics["total_bytes"] += len(packet)

    # Convert protocol numbers to names
    protocol_names = {6: "TCP", 17: "UDP"}
    metrics["protocols"] = {protocol_names.get(k, k): v for k, v in metrics["protocols"].items()}

    return metrics