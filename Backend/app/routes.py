from  flask import jsonify
from .utils import capture_packets
from .traffic_analysis import analyze_traffic
import os

def setup_routes(app):
    @app.route("/capture", methods=["GET"])
    def capture():
        """
        API endpoint to trigger packet capture.
        """
        try:
            # Capture 10 packets and save them to a file
            output_file = capture_packets(packet_count=10, output_file="captured_http_packets.pcap")

            # Check if the file was created
            if os.path.exists(output_file):
                return jsonify({"status": "success", "message": "Web activity Packets captured and saved successfully.", "file": output_file})
            else:
                return jsonify({"status": "error", "message": "Failed to capture packets."}), 500
        except Exception as e:
            return jsonify({"status": "error", "message": str(e)}), 500

    @app.route("/analyze", methods=["GET"])
    def analyze():
        """
        API endpoint to analyze captured traffic.
        """
        try:
            # Analyze the captured packets
            pcap_file = "captured_http_packets.pcap"
            if os.path.exists(pcap_file):
                metrics = analyze_traffic(pcap_file)
                return jsonify({"status": "success", "metrics": metrics})
            else:
                return jsonify({"status": "error", "message": "No capture file found. Please capture packets first."}), 404
        except Exception as e:
            return jsonify({"status": "error", "message": str(e)}), 500