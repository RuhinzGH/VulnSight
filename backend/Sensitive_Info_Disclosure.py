import requests
import re

# Headers and keywords to check for sensitive info
SENSITIVE_HEADERS = {
    "Server": "Server software and version info (e.g., Apache/2.4.51) - HIGH risk if revealed",
    "X-Powered-By": "Framework / language info (e.g., PHP/7.4.33) - HIGH risk if revealed",
    "X-AspNet-Version": "ASP.NET version info - HIGH risk",
    "X-AspNetMvc-Version": "ASP.NET MVC version info - HIGH risk",
}

# Keywords in page content that may indicate sensitive info
SENSITIVE_CONTENT_KEYWORDS = [
    r"warning:.*on line",          # PHP warnings/errors
    r"uncaught exception",         # Stack traces
    r"sql syntax.*mysql",          # SQL errors
    r"java\.lang\.",               # Java stack traces
    r"stack trace",                # Generic stack traces
    r"fatal error",                # Fatal errors
]

def check_sensitive_info(url):
    try:
        response = requests.get(url, timeout=10)
        headers = response.headers
        body = response.text.lower()

        found_issues = []

        print(f"\n--- Sensitive Information Disclosure Scan ---\nURL: {url}\n")

        # -----------------------------
        # 1. Check HTTP headers
        # -----------------------------
        for header, desc in SENSITIVE_HEADERS.items():
            if header in headers:
                # Dynamic severity based on header type
                if "version" in header.lower() or header in ["Server", "X-Powered-By"]:
                    severity = "HIGH"
                else:
                    severity = "MEDIUM"

                found_issues.append((f"{header} header detected: {headers[header]}", severity, desc))
                print(f"[-] {header} header found: {headers[header]} ⚠️ Severity: {severity}")

        # -----------------------------
        # 2. Check page content for sensitive keywords
        # -----------------------------
        for pattern in SENSITIVE_CONTENT_KEYWORDS:
            if re.search(pattern, body, re.IGNORECASE):
                # Dynamic severity based on type of pattern
                if any(k in pattern for k in ["sql", "java", "warning", "fatal"]):
                    severity = "HIGH"
                else:
                    severity = "MEDIUM"

                found_issues.append((f"Sensitive content detected matching '{pattern}'", severity, "Potential error/info disclosure"))
                print(f"[-] Sensitive content detected matching pattern '{pattern}' ⚠️ Severity: {severity}")

        # -----------------------------
        # 3. Summary if nothing found
        # -----------------------------
        if not found_issues:
            print("[+] No obvious sensitive information detected.")

        return found_issues

    except requests.exceptions.RequestException as e:
        print(f"Error accessing {url}: {e}")
        return None


if __name__ == "__main__":
    website = input("Enter a website URL to check: ").strip()
    if not website.startswith("http"):
        website = "http://" + website
    check_sensitive_info(website)
