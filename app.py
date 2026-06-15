from flask import Flask, render_template, request, send_file
import socket
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError
import threading

app = Flask(__name__)

# -------- PORT SCAN --------
def scan_ports(target):
    ports = [21,22,23,25,53,80,110,143,443,445,8080]
    open_ports = []

    def scan(port):
        s = socket.socket()
        s.settimeout(0.5)
        if s.connect_ex((target, port)) == 0:
            open_ports.append(port)
        s.close()

    threads = []
    for port in ports:
        t = threading.Thread(target=scan, args=(port,))
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    return open_ports

# -------- SUBDOMAIN SCAN --------
def scan_subdomains(domain):
    common = ["www", "mail", "ftp", "api", "dev"]
    found = []

    for sub in common:
        url = f"{sub}.{domain}"
        try:
            socket.gethostbyname(url)
            found.append(url)
        except:
            pass

    return found

# -------- HEADER CHECK --------
def check_headers(url):
    issues = []
    score = 100

    try:
        res = request.get(url, timeout=3)
        headers = res.headers

        checks = {
            "X-Content-Type-Options": ("Medium", 10),
            "X-Frame-Options": ("High", 20),
            "Content-Security-Policy": ("High", 25),
            "Strict-Transport-Security": ("Medium", 10)
        }

        for key, (level, penalty) in checks.items():
            if key not in headers:
                issues.append((f"Missing {key}", level))
                score -= penalty

        server = headers.get("Server", "Unknown")

        return issues, server, max(score, 0)

    except:
        return [("Connection failed", "High")], "Unknown", 0

# -------- RISK --------
def get_risk(score):
    if score > 80:
        return "Low"
    elif score > 50:
        return "Medium"
    else:
        return "High"

# -------- REPORT FILE --------
def generate_report(data):
    content = f"""
VULNERABILITY REPORT
----------------------
Server: {data['server']}
Score: {data['score']}
Risk: {data['risk']}

Open Ports:
{data['ports']}

Subdomains:
{data['subs']}

Issues:
{data['issues']}
"""
    with open("report.txt", "w") as f:
        f.write(content)

    return "report.txt"

# -------- ROUTE --------
@app.route('/', methods=['GET', 'POST'])
def home():
    result = None

    if request.method == 'POST':
        target = request.form['target']

        ports = scan_ports(target)
        subs = scan_subdomains(target)
        issues, server, score = check_headers("http://" + target)
        risk = get_risk(score)

        result = {
            "ports": ports,
            "subs": subs,
            "issues": issues,
            "server": server,
            "score": score,
            "risk": risk
        }

    return render_template("index.html", result=result)

# -------- DOWNLOAD --------
@app.route('/download')
def download():
    file = generate_report(app.last_result)
    return send_file(file, as_attachment=True)

if __name__ == "__main__":
    app.run(debug=True)