from scapy.all import sniff, wrpcap
import os

def capture_packets(interface=None, packet_count=10, output_file="captured_packets.pcap"):
    """
    Capture network packets and save them to a file.

    :param interface: Network interface to capture packets from (e.g., "eth0").
                     If None, Scapy will use the default interface.
    :param packet_count: Number of packets to capture.
    :param output_file: File to save the captured packets.
    """
    print(f"Starting packet capture on interface {interface or 'default'}...")

    # Capture packets
    packets = sniff(iface=interface, count=packet_count)

    # Save captured packets to a file
    wrpcap(output_file, packets)
    print(f"Captured {len(packets)} packets and saved to {output_file}")

    return output_file