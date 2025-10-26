
const sampleResults = [
  { id: "xss", name: "Cross-Site Scripting (XSS)", severity: "High", location: "/search.php", description: "Reflected XSS vulnerability found in search parameter. User input is not properly sanitized before being returned to the page.", fix: "Implement proper input validation and output encoding. Use frameworks that automatically escape output or dedicated security libraries." },
  { id: "http_headers", name: "HTTP Header Analysis", severity: "Medium", location: "Global", description: "Missing Content-Security-Policy header. This could allow execution of unauthorized scripts.", fix: "Add a Content-Security-Policy header with appropriate directives to restrict script sources." },
  { id: "ssl_tls", name: "SSL/TLS Certificate Check", severity: "Low", location: "https://example.com", description: "SSL certificate is valid but uses outdated TLS 1.1 protocol.", fix: "Update server configuration to use TLS 1.2 or 1.3 and disable older protocols." },
  { id: "clickjacking", name: "Clickjacking Detection", severity: "Medium", location: "Global", description: "X-Frame-Options header is missing, making the site vulnerable to clickjacking attacks.", fix: "Add X-Frame-Options header with DENY or SAMEORIGIN value to prevent your site from being framed." },
  { id: "insecure_cookies", name: "Insecure Cookies", severity: "Medium", location: "Session cookies", description: "Session cookies do not have the HttpOnly flag set, making them accessible to client-side scripts.", fix: "Set the HttpOnly flag on all sensitive cookies to prevent access from JavaScript." }
];

export default sampleResults;
