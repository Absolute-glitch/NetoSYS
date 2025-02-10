from scapy.all import sniff, wrpcap
import os

def capture_packets(interface=None, packet_count=10, output_file="captured_http_packets.pcap"):
    """
    Capture only HTTP network packets and save them to a file.

    :param interface: Network interface to capture packets from (e.g., "eth0").
                     If None, Scapy will use the default interface.
    :param packet_count: Number of packets to capture.
    :param output_file: File to save the captured packets.
    """
    print(f"Starting HTTP packet capture on interface {interface or 'default'}...")

    # BPF filter to capture only HTTP traffic and HTTPS (port 80 for HTTP, port 8080 for alternative HTTP, port 443 for HTTPS)
    bpf_filter = "tcp port 80 or tcp port 443 or tcp port 8080"

    # Capture packets
    packets = sniff(iface=interface, count=packet_count, filter=bpf_filter)

    # Save captured packets to a file
    wrpcap(output_file, packets)
    print(f"Captured {len(packets)} HTTP packets and saved to {output_file}")

    return output_file