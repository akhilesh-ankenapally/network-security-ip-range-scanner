"""
app.py - Flask web application backend for Network Security IP Range Scanner.
Project 3: College Cybersecurity Assignment Prototype
"""

from flask import Flask, render_template, request, jsonify
import scanner

app = Flask(__name__)


@app.route("/")
def index():
    """Renders the main scanner web dashboard."""
    return render_template("index.html")


@app.route("/api/scan", methods=["POST"])
def scan():
    """
    Scans the requested IP range and returns active/inactive hosts in JSON format.
    Expects JSON body: { "target": "192.168.1.1-20" }
    """
    data = request.get_json(silent=True) or {}
    target = data.get("target", "").strip()

    if not target:
        # Fallback to form data if submitted via traditional form
        target = request.form.get("target", "").strip()

    if not target:
        return jsonify({
            "success": False,
            "error": "IP range target is required. Example: 192.168.1.1-20 or 192.168.1.0/28"
        }), 400

    try:
        results = scanner.scan_range(target)
        return jsonify(results), 200
    except ValueError as val_err:
        return jsonify({
            "success": False,
            "error": str(val_err)
        }), 400
    except Exception as exc:
        return jsonify({
            "success": False,
            "error": f"Internal scanner failure: {str(exc)}"
        }), 500


@app.route("/api/health", methods=["GET"])
def health():
    """Health check endpoint for service status."""
    return jsonify({
        "status": "healthy",
        "service": "Network Security IP Range Scanner",
        "version": "1.0.0"
    }), 200


if __name__ == "__main__":
    print("=========================================================")
    print("  Project 3: Network Security IP Range Scanner Prototype")
    print("  Running on: http://127.0.0.1:5000")
    print("=========================================================")
    app.run(host="127.0.0.1", port=5000, debug=False)
