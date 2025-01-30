from flask import jsonify
from . utils import capture_packets

@app.route('/capture')
def capture():
    packets = capture_packets()
    return jsonify({"message": f"Captured {len(packets)} packets"})
from . import app  # Relative import for the app object