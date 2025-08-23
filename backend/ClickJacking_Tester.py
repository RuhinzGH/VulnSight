import tkinter as tk
from tkinter import messagebox
import webbrowser
import requests
from tkinterweb import HtmlFrame  # pip install tkinterweb

# -----------------------------
# Clickjacking header check
# -----------------------------
def check_clickjacking(url):
    """
    Header check + severity grading.
    Returns a dict of results for integration with simulation.
    """
    results = {}
    severity = "LOW"

    try:
        response = requests.get(url, timeout=10)
        headers = response.headers

        # X-Frame-Options
        x_frame = headers.get("X-Frame-Options")
        if x_frame and x_frame.upper() in ["DENY", "SAMEORIGIN"]:
            results["X-Frame-Options"] = "SAFE"
        elif x_frame:
            results["X-Frame-Options"] = f"UNUSUAL ({x_frame})"
        else:
            results["X-Frame-Options"] = "MISSING"

        # CSP frame-ancestors
        csp = headers.get("Content-Security-Policy")
        if csp and "frame-ancestors" in csp.lower():
            frame_ancestors = csp.lower().split("frame-ancestors")[1].split(";")[0].strip()
            if frame_ancestors in ("*", "'self'"):
                results["CSP frame-ancestors"] = "SAFE"
            else:
                results["CSP frame-ancestors"] = f"PERMISSIVE ({frame_ancestors})"
        else:
            results["CSP frame-ancestors"] = "MISSING"

        # Severity determination
        if ("MISSING" in results["X-Frame-Options"] or "UNUSUAL" in results["X-Frame-Options"]) and \
           ("MISSING" in results["CSP frame-ancestors"] or "PERMISSIVE" in results["CSP frame-ancestors"]):
            severity = "HIGH"
        elif "SAFE" not in results["X-Frame-Options"] or "SAFE" not in results["CSP frame-ancestors"]:
            severity = "MEDIUM"
        results["Severity"] = severity

    except requests.exceptions.RequestException:
        results = {"Error": "Unable to reach URL"}

    return results

# -----------------------------
# Improved Simulation UI
# -----------------------------
def simulate_clickjacking(url):
    """
    Opens a Tkinter window demonstrating a more realistic clickjacking overlay.
    """
    sim_window = tk.Tk()
    sim_window.title("Clickjacking Simulation - VulnSight")
    sim_window.geometry("800x600")

    # Instructions
    tk.Label(sim_window, text="Clickjacking Demo (Safe / Educational)", font=("Arial", 14)).pack(pady=10)
    tk.Label(sim_window, text=f"Target URL: {url}", fg="blue").pack(pady=5)

    # Frame for the embedded site
    iframe_frame = tk.Frame(sim_window, width=700, height=400, bg="lightgray", relief="sunken", borderwidth=2)
    iframe_frame.pack(pady=20, fill="both", expand=True)

    # HtmlFrame for safe site embedding
    html_frame = HtmlFrame(iframe_frame, horizontal_scrollbar="auto")
    html_frame.load_website(url)  # loads the real site inside the gray frame
    html_frame.pack(fill="both", expand=True)

    # Semi-transparent red overlay representing malicious click interception
    overlay = tk.Frame(iframe_frame, width=700, height=400, bg="red")
    overlay.place(x=0, y=0)
    overlay_label = tk.Label(overlay, text="Malicious overlay (clicks intercepted!)", fg="white", bg="red")
    overlay_label.place(relx=0.5, rely=0.5, anchor="center")

    # Click binding to show educational popup
    def click_overlay(event):
        messagebox.showinfo("Clickjacking Simulation",
                            "This demonstrates how clicks could be hijacked.\n(No real harm done!)")
    overlay.bind("<Button-1>", click_overlay)

    # Button to open real site safely in browser
    tk.Button(sim_window, text="Open real site in browser", command=lambda: webbrowser.open(url)).pack(pady=10)

    sim_window.mainloop()

# -----------------------------
# Main program
# -----------------------------
if __name__ == "__main__":
    url = input("Enter a URL to test for clickjacking: ").strip()
    if not url.startswith("http"):
        url = "http://" + url

    results = check_clickjacking(url)

    print("\n--- Clickjacking Test Result ---")
    for k, v in results.items():
        print(f"{k}: {v}")

    # Launch the interactive simulation
    simulate_clickjacking(url)
