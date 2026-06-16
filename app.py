from flask import Flask, render_template, request, jsonify
from scanner.port_scanner import scan_ports
from scanner.web_scanner import scan_website

app = Flask(__name__)

def normalize_target(target):
    if not target.startswith("http"):
        return "http://" + target
    return target

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/scan", methods=["POST"])
def scan():
    target = request.json.get("target")

    url = normalize_target(target)

    port_results = scan_ports(target)
    web_results = scan_website(url)

    return jsonify({
        "ports": port_results,
        "web": web_results
    })

if __name__ == "__main__":
    app.run(debug=True)