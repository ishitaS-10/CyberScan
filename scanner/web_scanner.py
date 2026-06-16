import requests

def scan_website(url):
    findings = {}

    try:
        response = requests.get(url, timeout=5)

        headers = response.headers

        findings["Security Headers"] = {
            "X-Frame-Options": headers.get("X-Frame-Options", "Missing"),
            "Content-Security-Policy": headers.get("Content-Security-Policy", "Missing"),
            "Strict-Transport-Security": headers.get("Strict-Transport-Security", "Missing")
        }

        findings["Server"] = headers.get("Server", "Unknown")

        if "https" not in url:
            findings["SSL"] = "❌ Not Secure (HTTP)"
        else:
            findings["SSL"] = "✅ Secure (HTTPS)"

    except Exception as e:
        findings["Error"] = str(e)

    return findings