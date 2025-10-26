# server.py
"""
VulnSight backend (async, URLScan integrated) with MySQL storage
Supports logged-in and guest scans (guest scans stored with user_id=None)
"""
import os
import time
import uuid
import json
import asyncio
import hashlib
import traceback
import importlib
from typing import List, Dict, Any, Optional

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from dotenv import load_dotenv
import mysql.connector
from mysql.connector import Error
import httpx
import aiosmtplib
from email.message import EmailMessage
from email.utils import formataddr
import base64
from groq import Groq



# ------------------- Load environment -------------------
load_dotenv()
MYSQL_HOST = os.getenv("MYSQL_HOST", "localhost")
MYSQL_USER = os.getenv("MYSQL_USER")
MYSQL_PASS = os.getenv("MYSQL_PASS")
MYSQL_DB = os.getenv("MYSQL_DB")
MYSQL_PORT = int(os.getenv("MYSQL_PORT", 3306))

SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", 587))
SMTP_USER = os.getenv("SMTP_USER")
SMTP_PASS = os.getenv("SMTP_PASS")

URLSCAN_API_KEY = os.getenv("URLSCAN_API_KEY")
GROQ_API_KEY = os.getenv("GROQ_API_KEY")
groq_client = Groq(api_key=GROQ_API_KEY)

# ------------------- MySQL connection (single connection object) -------------------
conn = None
try:
    conn = mysql.connector.connect(
        host=MYSQL_HOST,
        user=MYSQL_USER,
        password=MYSQL_PASS,
        database=MYSQL_DB,
        port=MYSQL_PORT,
        autocommit=False,
    )
    print("✅ MySQL connection successful")
except Error as e:
    print("❌ MySQL connection failed:", e)
    conn = None

# ------------------- FastAPI setup -------------------
app = FastAPI()

# Important: Session middleware before CORS routing-related operations that need sessions.
app.add_middleware(
    SessionMiddleware,
    secret_key=os.getenv("SESSION_SECRET", "supersecretkey123"),
    same_site="lax",
    https_only=False,
)

# Local dev origins
_origins = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"],
)

# ------------------- Models -------------------
class ScanRequest(BaseModel):
    url: str
    vulnerabilities: List[str] = []
    email: str | None = None

class AuthRequest(BaseModel):
    email: str
    password: str
    name: str | None = None

class SendReportRequest(BaseModel):
    to: str
    subject: str
    body: str
    pdf_base64: str
    filename: str

# ------------------- Tools mapping -------------------
TOOLS = {
    "clickjacking": "Tools.ClickJacking_Tester",
    "cors": "Tools.CORS_detection",
    "directory_listing": "Tools.Directory_Listing_Check",
    "http_headers": "Tools.HTTP_Security_Header_Analysis",
    "insecure_cookies": "Tools.Missing_Cookies",
    "open_redirect": "Tools.OpenRedirect",
    "outdated_software": "Tools.outdates_software",
    "info_disclosure": "Tools.Sensitive_Info_Disclosure",
    "ssl_tls": "Tools.SSL_TLS_checker",
    "xss": "Tools.XSS",
    "sql_injection": "Tools.SQL_injection",
    "path_traversal": "Tools.pathtraversal"
}

# ------------------- Helpers -------------------
def _call_tool_callable(callable_obj, url: str):
    try:
        return callable_obj(url)
    except TypeError:
        try:
            return callable_obj(url, timeout=10)
        except TypeError:
            return callable_obj(target=url)

def classify_blocked_response(tool_result: dict) -> dict:
    if not isinstance(tool_result, dict):
        return tool_result
    headers = tool_result.get("headers") or {}
    status = tool_result.get("status_code") or tool_result.get("response_status_code")
    text_snippet = tool_result.get("text_snippet", "") or tool_result.get("body_snippet", "")
    blocked_reasons = []
    if status in (403, 429):
        blocked_reasons.append(f"HTTP {status}")
    if text_snippet:
        lower_text = text_snippet.lower()
        for keyword in ["captcha", "verify you are human", "cloudflare", "bot", "challenge", "access denied"]:
            if keyword in lower_text:
                blocked_reasons.append(keyword)
    if blocked_reasons:
        return {
            "error": "Target likely blocked scan / WAF protection triggered",
            "severity": "Unknown",
            "description": "Scan could not retrieve headers/content due to bot protection/firewall.",
            "fix": "Manual verification required; optionally use browser-based scan mode.",
            "references": [],
            "_meta": tool_result.get("_meta", {}),
            "blocked_reasons": blocked_reasons
        }
    return tool_result

def normalize_results(raw_results: Dict[str, Any]) -> List[Dict[str, Any]]:
    results = []
    for vuln, data in raw_results.items():
        name = vuln.replace("_", " ").title()
        severity = "Unknown"
        description = "No description provided."
        fix = "No fix recommendation available."
        references = [f"OWASP {name} Prevention", "CWE Reference", "NIST Guidelines"]
        if isinstance(data, dict):
            if "error" in data:
                description = data.get("description", data["error"])
                severity = data.get("severity", "Unknown")
                fix = data.get("fix", "Check backend service")
            else:
                name = data.get("name", name)
                severity = data.get("severity", severity)
                description = data.get("description", description)
                fix = data.get("fix", fix)
                references = data.get("references", references)
        results.append({
            "id": vuln,
            "status": "ok" if "error" not in str(data).lower() else "error",
            "name": name,
            "severity": severity,
            "description": description,
            "fix": fix,
            "references": references,
            "details": data
        })
    return results

# ------------------- Exception handler -------------------
@app.exception_handler(Exception)
async def handle_exception(request: Request, exc: Exception):
    # print stack trace server-side and return safe JSON message
    print("❌ Unhandled exception:", exc)
    traceback.print_exc()
    return JSONResponse(content={"status": "error", "message": str(exc)}, status_code=500)

# ------------------- Routes -------------------
@app.get("/")
def home():
    return {"message": "Hello from VulnSight backend!"}

@app.get("/cors-test")
def cors_test():
    return {"message": "CORS is working"}

# ------------------- Signup -------------------
@app.post("/signup")
async def signup(payload: AuthRequest):
    if conn is None:
        return {"status": "error", "message": "Database not connected"}
    email, password, name = payload.email, payload.password, payload.name or "User"
    if not email or not password:
        return {"status": "error", "message": "Email and password are required"}
    try:
        cur = conn.cursor(dictionary=True)
        try:
            cur.execute("SELECT id FROM users WHERE email=%s", (email,))
            if cur.fetchone():
                return {"status": "error", "message": "User already exists"}
            password_hash = hashlib.sha256(password.encode()).hexdigest()
            cur.execute("INSERT INTO users (name,email,password_hash) VALUES (%s,%s,%s)", (name,email,password_hash))
            conn.commit()
            return {"status": "success", "message": "Signup successful"}
        finally:
            cur.close()
    except Error as e:
        return {"status": "error", "message": str(e)}

# ------------------- Login -------------------
@app.post("/login")
async def login_user(request: Request, payload: AuthRequest):
    if conn is None:
        return {"status":"error","message":"Database not connected"}
    email, password = payload.email, payload.password
    if not email or not password:
        return {"status": "error", "message": "Email and password required"}
    try:
        cur = conn.cursor(dictionary=True)
        try:
            cur.execute("SELECT * FROM users WHERE email=%s", (email,))
            user = cur.fetchone()
            if not user:
                return {"status": "error", "message": "Invalid email or password"}
            password_hash = hashlib.sha256(password.encode()).hexdigest()
            if user.get("password_hash") != password_hash:
                return {"status": "error", "message": "Invalid email or password"}
            # set session
            request.session["email"] = user["email"]
            request.session["user_id"] = user["id"]
            return {"status": "success", "message": "Login successful", "user": {"email":user["email"], "id":user["id"], "name":user.get("name")}}
        finally:
            cur.close()
    except Error as e:
        return {"status": "error", "message": str(e)}

# ------------------- Logout -------------------
@app.post("/logout")
async def logout_user(request: Request):
    request.session.clear()
    response = JSONResponse({"status": "success", "message": "Logged out successfully"})
    # session cookie is server-managed; instruct client to clear if needed
    response.delete_cookie("session")
    return response

# ------------------- Execute scan helpers -------------------
async def fetch_urlscan_data_async(url:str) -> dict:
    if not URLSCAN_API_KEY:
        return {"error":"URLSCAN_API_KEY not configured","_source":"urlscan"}
    headers = {"API-Key": URLSCAN_API_KEY,"Content-Type":"application/json"}
    payload = {"url":url,"visibility":"public"}
    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            submit_resp = await client.post("https://urlscan.io/api/v1/scan/",json=payload,headers=headers)
            submit_resp.raise_for_status()
            j = submit_resp.json()
            uuid_val = j.get("uuid")
            if not uuid_val: return {"error":"Failed to get urlscan UUID","_source":"urlscan"}
            for _ in range(5):
                await asyncio.sleep(3)
                result_resp = await client.get(f"https://urlscan.io/api/v1/result/{uuid_val}/",headers=headers)
                if result_resp.status_code==200:
                    data=result_resp.json()
                    data["_source"]="urlscan"
                    return data
            return {"error":"URLScan result not ready","_source":"urlscan","uuid":uuid_val}
    except Exception as e:
        return {"error":str(e),"_source":"urlscan"}

async def run_tool_async(vuln:str,url:str) -> tuple:
    module_path = TOOLS.get(vuln)
    if not module_path:
        return vuln, {"error":f"Tool '{vuln}' not found"}
    try:
        module = importlib.import_module(module_path)
    except Exception as e:
        return vuln, {"error":f"ImportError: {str(e)}"}
    callable_obj=None
    for name in ("run","scan","main","check"):
        if hasattr(module,name) and callable(getattr(module,name)):
            callable_obj=getattr(module,name)
            break
    if callable_obj is None:
        if callable(module):
            callable_obj=module
        else:
            return vuln, {"error":f"No callable found in {module_path}"}
    result = await asyncio.to_thread(_call_tool_callable,callable_obj,url)
    result = classify_blocked_response(result)
    return vuln,result
@app.post("/scan")
async def scan_url(payload: ScanRequest, request: Request):
    url = payload.url
    selected_vulns = payload.vulnerabilities or list(TOOLS.keys())

    from urllib.parse import urlparse
    parsed = urlparse(url or "")
    if not (parsed.scheme and parsed.netloc):
        return {"status": "error", "message": "Invalid URL provided", "results": [], "urlscan": {}, "llm_summary": ""}

    # ------------------- Determine user -------------------
    session_email = request.session.get("email")
    session_user_id = request.session.get("user_id")
    user_id: Optional[int] = None

    if session_email and session_user_id and conn:
        def verify_user(email: str, uid: int):
            curv = conn.cursor(dictionary=True)
            try:
                curv.execute("SELECT id FROM users WHERE email=%s AND id=%s", (email, uid))
                row = curv.fetchone()
                return row["id"] if row else None
            finally:
                curv.close()

        try:
            verified_id = await asyncio.to_thread(verify_user, session_email, session_user_id)
            if verified_id:
                user_id = verified_id
            else:
                request.session.clear()
                user_id = None
        except Exception:
            request.session.clear()
            user_id = None
    else:
        user_id = None  # guest

    # ------------------- Run vulnerability tools -------------------
    async def run_all_tools():
        tasks = [run_tool_async(v, url) for v in selected_vulns]
        completed = await asyncio.gather(*tasks, return_exceptions=False)
        return {v: r for v, r in completed}

    try:
        raw_results = await run_all_tools()
    except Exception as e:
        print("❌ Tool execution error:", e)
        raw_results = {v: {"error": f"Tool run failed: {str(e)}"} for v in selected_vulns}

    # ------------------- URLScan fetch -------------------
    try:
        urlscan_data = await fetch_urlscan_data_async(url)
    except Exception as e:
        print("❌ URLScan error:", e)
        urlscan_data = {"error": str(e), "_source": "urlscan"}

    # ------------------- LLM explanation (returns plain string) -------------------
    async def explain_vulnerabilities_text(raw_results: dict) -> str:
        # If GROQ_API_KEY is missing, bail early
        if not GROQ_API_KEY:
            print("⚠ GROQ_API_KEY not configured; skipping LLM call.")
            return "LLM not configured."

        try:
            tools_list = normalize_results(raw_results)
            prompt = (
                "You are a sophisticated cybersecurity expert. Your response **MUST** be structured using "
                "Markdown. Start with the main heading (`##`), and use a smaller subheading (`###`) for the primary vulnerability/scan target. "
                "**If you include any sub-topics or related findings, use an even smaller heading (`####`) for those.** "
                "Ensure the risk and remediation paragraphs are separated by a double newline.\n\n"
                
                # This line keeps the string structure stable - NO CHANGE
                "Please begin your structured output immediately below this line, with **NO introductory text** or **header filler**:\n\n" # <--- SLIGHTLY FIRMER INSTRUCTION
                
                "**FORMAT EXAMPLE (START IMMEDIATELY WITH THE COMBINED HEADING):**\n"
                "### Finding Name\n" # <--- REMOVED: (e.g., Clickjacking)
                "#### Sub-Topic Name\n" # <--- REMOVED: (Smaller) AND changed to 'Name'
                "**Risk:** A short, sophisticated description of the impact.\n\n"
                "**Remediation:** A concise, confident instruction on how to fix it.\n\n"
                "--- START ANALYSIS ---\n\n"

               
            )
            for tool in tools_list:
                name = tool.get("name", tool.get("id", "unknown"))
                desc = tool.get("description", "")
                prompt += f"- {name}: {desc}\n"

            # Use asyncio.to_thread to call blocking SDK
            def call_groq():
                return groq_client.chat.completions.create(
                    model="llama-3.3-70b-versatile",
                    messages=[
                        {"role": "system", "content": "You are a concise cybersecurity analyst."},
                        {"role": "user", "content": prompt},
                    ],
                    max_tokens=700,
                    temperature=0.2,
                )

            response = await asyncio.to_thread(call_groq)

            # Debug: print the raw response to logs so you can inspect structure
            try:
                print("🔎 Groq raw response type:", type(response))
                # safe repr of a small chunk
                print("🔎 Groq response (repr head):", repr(response)[:1000])
            except Exception:
                pass

            # Extract text robustly
            explanation_text = None
            try:
                if hasattr(response, "choices") and response.choices:
                    choice = response.choices[0]
                    # Prefer message.content
                    if getattr(choice, "message", None) and getattr(choice.message, "content", None):
                        explanation_text = choice.message.content.strip()
                    # Fallback to text attribute
                    elif getattr(choice, "text", None):
                        explanation_text = choice.text.strip()
                # final fallback
                if not explanation_text:
                    explanation_text = getattr(response, "output_text", None) or "No explanation generated."
            except Exception as e:
                print("❌ LLM parse error:", e)
                explanation_text = "Failed to parse LLM response."

            # Show short debug snippet
            print("✅ LLM explanation (first 200 chars):", (explanation_text or "")[:200])
            return explanation_text or "No explanation generated."
        except Exception as e:
            print("❌ LLM error:", e)
            return "Failed to generate explanation."

    llm_summary_text = await explain_vulnerabilities_text(raw_results)

        # ------------------- Risk computation -------------------
    normalized = normalize_results(raw_results)
    try:
        high_count = sum(1 for r in normalized if r.get("severity", "").lower() in ("critical", "high"))
        risk_score = min(100, high_count * 10)
        if high_count >= 3:
            risk_level = "High"
        elif high_count == 0:
            risk_level = "Low"
        else:
            risk_level = "Medium"
    except Exception:
        risk_score = 0
        risk_level = "Unknown"

    # ------------------- Save scan to DB -------------------
    scan_uuid = str(uuid.uuid4())
    if user_id is None:
        print("⚠️  Guest scan detected — skipping database save (no user_id).")
    else:
        try:
            if conn:
                cur = conn.cursor()
                try:
                    cur.execute(
                        """
                        INSERT INTO scan
                        (scan_uuid, user_id, url, timestamp, scan_duration, risk_score, risk_level, tool_version, results, created_at)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, NOW())
                        """,
                        (
                            scan_uuid,
                            user_id,
                            url,
                            int(time.time()),
                            "N/A",
                            risk_score,
                            risk_level,
                            "VulnSight v1.0",
                            json.dumps({
                                "tools": normalized,
                                "urlscan": urlscan_data,
                                "llm_summary": llm_summary_text,
                            }),
                        ),
                    )
                    conn.commit()
                    print(f"✅ Scan inserted: {scan_uuid} (user_id={user_id})")
                finally:
                    cur.close()
        except Error as e:
            print("⚠️ Skipped DB insert (guest or invalid user):", e)


        

    # ------------------- Return response -------------------
    return {
        "status": "success",
        "scan_id": scan_uuid,
        "results": normalized,
        "urlscan": urlscan_data,
        "llm_summary": llm_summary_text,  # plain string now
        "user_id": user_id,
        "logged_in_as": session_email if user_id else None,
        "risk_score": risk_score,
        "risk_level": risk_level,
    }

# ------------------- Current user -------------------
@app.get("/current-user")
async def current_user(request: Request):
    # Return session user details if present
    email = request.session.get("email")
    user_id = request.session.get("user_id")
    if email and user_id and conn:
        cur = conn.cursor(dictionary=True)
        try:
            cur.execute("SELECT id, name, email FROM users WHERE id=%s", (user_id,))
            row = cur.fetchone()
            if row:
                return {"email": row.get("email"), "id": row.get("id"), "name": row.get("name")}
            else:
                # session invalid -> clear
                request.session.clear()
                return {"email": None, "id": None, "name": None}
        finally:
            cur.close()
    return {"email": None, "id": None, "name": None}

# ------------------- User scans -------------------
@app.get("/user-scans")
async def user_scans(request: Request):
    # Return recent scans for logged-in user only
    user_id = request.session.get("user_id")
    if not user_id:
        return {"status":"error","message":"Not logged in","scans":[]}
    if conn is None:
        return {"status":"error","message":"Database not connected","scans":[]}
    try:
        cur = conn.cursor(dictionary=True)
        try:
            # LIMIT and ORDER to avoid heavy server-side sorts that triggered "out of sort memory"
            cur.execute("SELECT scan_uuid, url, timestamp, scan_duration, risk_score, risk_level, tool_version, created_at FROM scan WHERE user_id=%s ORDER BY timestamp DESC LIMIT 50", (user_id,))
            rows = cur.fetchall()
            return {"status":"success","scans": rows}
        finally:
            cur.close()
    except Error as e:
        print("❌ user-scans DB error:", e)
        return {"status":"error","message": str(e), "scans": []}

# ------------------- Send report endpoint -------------------
@app.post("/send-report")
async def send_report(payload: SendReportRequest):
    if not all([payload.to,payload.subject,payload.body,payload.pdf_base64,payload.filename]):
        return {"status":"error","message":"Missing fields in request"}
    try:
        pdf_bytes = base64.b64decode(payload.pdf_base64)
        msg = EmailMessage()
        msg["From"]=formataddr(("VulnSight",SMTP_USER))
        msg["To"]=payload.to
        msg["Subject"]=payload.subject
        msg.set_content(payload.body)
        msg.add_attachment(pdf_bytes, maintype="application", subtype="pdf", filename=payload.filename)
        await aiosmtplib.send(msg, hostname=SMTP_HOST, port=SMTP_PORT, start_tls=True, username=SMTP_USER, password=SMTP_PASS, validate_certs=False)
        return {"status":"success","message":"Email sent successfully!"}
    except Exception as e:
        print("❌ Email sending error:",e)
        return {"status":"error","message":str(e)}