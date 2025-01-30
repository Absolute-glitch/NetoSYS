from scapy.all import sniff

def capture_packets(count=20):
    """
    Capturing network packets.
    :param count: Number of packets to capture.
    :return: List of captured packets.
    """
    packets = sniff(count=count)
    return packets

