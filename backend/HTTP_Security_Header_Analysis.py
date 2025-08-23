import requests

# Security headers with explanation, weight, and severity if missing
SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "desc": "Forces HTTPS connections, preventing downgrade attacks.",
        "weight": 2,
        "severity": "HIGH"
    },
    "X-Content-Type-Options": {
        "desc": "Prevents MIME type sniffing; protects against content-type attacks.",
        "weight": 1,
        "severity": "MEDIUM"
    },
    "X-Frame-Options": {
        "desc": "Prevents clickjacking by controlling iframe embedding.",
        "weight": 2,
        "severity": "HIGH"
    },
    "X-XSS-Protection": {
        "desc": "Legacy XSS filter in some browsers (not very relevant now).",
        "weight": 1,
        "severity": "LOW"
    },
    "Content-Security-Policy": {
        "desc": "Controls which resources/scripts can be loaded/executed.",
        "weight": 3,
        "severity": "HIGH"
    },
    "Referrer-Policy": {
        "desc": "Controls what referrer information is sent to other sites.",
        "weight": 1,
        "severity": "LOW"
    },
    "Permissions-Policy": {
        "desc": "Controls browser features like camera, microphone, geolocation.",
        "weight": 2,
        "severity": "MEDIUM"
    }
}

def grade_score(score, max_score):
    """Return a letter grade based on score percentage"""
    percent = (score / max_score) * 100
    if percent >= 90:
        return "A"
    elif percent >= 75:
        return "B"
    elif percent >= 60:
        return "C"
    elif percent >= 40:
        return "D"
    else:
        return "F"

def check_security_headers(url):
    try:
        response = requests.get(url, timeout=5)
        headers = response.headers
        total_weight = sum(h["weight"] for h in SECURITY_HEADERS.values())
        score = 0

        print(f"\n--- HTTP Security Header Analysis ---\nURL: {url}\n")

        for header, info in SECURITY_HEADERS.items():
            if header in headers:
                print(f"[+] {header} is present: {info['desc']} (Safe)")
                score += info["weight"]
            else:
                print(f"[-] {header} is MISSING: {info['desc']} ⚠️ Severity: {info['severity']}")

        grade = grade_score(score, total_weight)
        print(f"\nOverall Security Grade: {grade} / A (Best)")
        return grade

    except requests.exceptions.RequestException as e:
        print(f"Error accessing {url}: {e}")
        return None

if __name__ == "__main__":
    website = input("Enter a website URL to check: ").strip()
    if not website.startswith("http"):
        website = "http://" + website
    check_security_headers(website)
