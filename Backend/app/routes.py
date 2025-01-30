from Flask import jsonify
from backend.app.utils import capture_packets

@app.route('/capture')
def capture():
    packets = capture_packets()
    return jsonify({"message": f"Captured {len(packets)} packets"})