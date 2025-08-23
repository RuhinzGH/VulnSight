import requests
import re
from bs4 import BeautifulSoup
from urllib.parse import urljoin

def check_directory_listing(url):
    results = []
    files_found = []

    try:
        response = requests.get(url, timeout=10, allow_redirects=True)
        status_code = response.status_code
        content_type = response.headers.get("Content-Type", "")
        body = response.text
        body_lower = body.lower()

        # -----------------------------
        # 1. Common Directory Listing Markers
        # Require at least one classic marker to confirm listing
        # -----------------------------
        markers = ["index of /", "directory listing for", "parent directory"]
        marker_hits = [m for m in markers if m in body_lower]
        if marker_hits:
            results.append((f"Directory listing detected via marker(s): {', '.join(marker_hits)}", "HIGH"))

        # -----------------------------
        # 2. Regex Pattern Check for File Links
        # Only consider relative links or files in the directory
        # -----------------------------
        file_pattern = r"<a\s+href\s*=\s*\"([^\"]+\.[a-z0-9]{1,5})\""
        matches = re.findall(file_pattern, body, re.IGNORECASE)
        for f in matches:
            if not f.startswith("http") and not f.startswith("mailto:"):
                files_found.append(urljoin(url, f))

        # -----------------------------
        # 3. Status Code / Minimal HTML Fallback
        # Only flag minimal HTML directories if markers found
        # -----------------------------
        if status_code == 200 and url.endswith("/") and len(re.findall(r"<[a-z]+", body_lower)) < 50:
            if marker_hits:  # only confirm if marker exists
                results.append(("Possible directory listing (200 OK on dir path, minimal HTML)", "MEDIUM"))

        # -----------------------------
        # 4. MIME Type + HTML Title Check
        # -----------------------------
        if "text/html" in content_type and "<title>index of" in body_lower and marker_hits:
            results.append(("Directory listing detected via MIME type + HTML title", "HIGH"))

        # -----------------------------
        # 5. Parent Directory Traversal Indicators
        # -----------------------------
        if "../" in body_lower and marker_hits:
            results.append(("Parent directory navigation link detected ('../')", "HIGH"))

        # -----------------------------
        # 6. Dummy File Behavior
        # -----------------------------
        dummy_url = urljoin(url, "nonexistentfile12345.txt")
        dummy_resp = requests.get(dummy_url, timeout=10)
        if dummy_resp.status_code == 200 and len(dummy_resp.text) < 100:
            results.append(("Suspicious behavior on nonexistent file (200 OK)", "LOW"))

        # -----------------------------
        # 7. Final Decision: Only list files if markers exist
        # -----------------------------
        if not marker_hits:
            files_found = []  # remove false positives on normal pages

        # -----------------------------
        # 8. Display Results
        # -----------------------------
        print("\n--- Scan Result ---")
        print(f"URL: {url}")

        if results:
            for issue, severity in results:
                print(f"- {issue}\n  Severity: {severity}")
        else:
            print("No directory listing detected.")

        if files_found:
            print("\nFiles found:")
            for f in sorted(set(files_found)):
                print(f" - {f}")

    except requests.exceptions.RequestException as e:
        print(f"Error accessing {url}: {e}")


if __name__ == "__main__":
    target_url = input("Enter a URL to check: ").strip()
    if not target_url.startswith("http"):
        target_url = "http://" + target_url
    check_directory_listing(target_url)
