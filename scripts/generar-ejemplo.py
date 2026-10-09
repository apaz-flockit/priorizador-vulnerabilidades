"""Genera un reporte de vulnerabilidades de ejemplo (estilo Nessus) en CSV y XLSX."""
import csv, random, sys, os

random.seed(42)
out = sys.argv[1] if len(sys.argv) > 1 else "public"

HOSTS = [
    ("10.0.1.10", "Producción"), ("10.0.1.11", "Producción"), ("10.0.1.12", "Producción"),
    ("10.0.2.20", "Producción"), ("10.0.2.21", "Testing"), ("10.0.3.30", "Desarrollo"),
    ("10.0.3.31", "Desarrollo"), ("192.168.10.5", "Producción"), ("192.168.10.6", "Testing"),
    ("192.168.10.7", "Desarrollo"), ("172.16.0.4", "Producción"), ("172.16.0.9", "Testing"),
]

# (nombre, cve, cvss, riesgo, puerto, sinopsis, solución, exploit, cantidad de hosts)
VULNS = [
    ("Microsoft Windows SMB Server Multiple Vulnerabilities (MS17-010)", "CVE-2017-0143,CVE-2017-0144", 8.1, "Critical", "445",
     "The remote Windows host is affected by multiple remote code execution vulnerabilities (EternalBlue).",
     "Apply the security update MS17-010 from Microsoft.", "true", 3),
    ("Apache Log4j Remote Code Execution (Log4Shell)", "CVE-2021-44228", 10.0, "Critical", "8080",
     "A Java logging library on the remote host is affected by a remote code execution vulnerability.",
     "Upgrade to Apache Log4j version 2.17.1 or later.", "true", 2),
    ("Apache HTTP Server < 2.4.58 Multiple Vulnerabilities", "CVE-2023-45802,CVE-2023-43622", 7.5, "High", "443",
     "The version of Apache httpd installed on the remote host is prior to 2.4.58.",
     "Upgrade to Apache HTTP Server version 2.4.58 or later.", "false", 4),
    ("OpenSSH < 9.8 RCE (regreSSHion)", "CVE-2024-6387", 8.1, "High", "22",
     "The version of OpenSSH installed on the remote host is prior to 9.8 and is affected by a signal handler race condition.",
     "Upgrade to OpenSSH version 9.8 or later.", "true", 5),
    ("PHP Unsupported Version Detection", "", 10.0, "Critical", "80",
     "The remote host contains an unsupported version of PHP (end of life).",
     "Upgrade to a version of PHP that is currently supported.", "false", 2),
    ("SQL Injection in login form (/app/login.php)", "", 9.8, "Critical", "443",
     "The web application is vulnerable to SQL injection through the 'user' parameter.",
     "Use parameterized queries / prepared statements and validate all user input.", "true", 1),
    ("Cross-Site Scripting (XSS) reflejado en buscador", "", 6.1, "Medium", "443",
     "The 'q' parameter is reflected without encoding, allowing script injection.",
     "Encode output and implement a Content-Security-Policy.", "false", 1),
    ("Default Credentials on Tomcat Manager", "", 9.8, "Critical", "8080",
     "The Apache Tomcat Manager interface accepts the default username and password (tomcat/tomcat).",
     "Change the default password and restrict access to the manager interface.", "true", 1),
    ("SSL Version 2 and 3 Protocol Detection", "CVE-2014-3566", 7.5, "High", "443",
     "The remote service accepts connections encrypted using SSL 2.0 and/or SSL 3.0 (POODLE).",
     "Disable SSL 2.0 and 3.0. Use TLS 1.2 or later.", "false", 4),
    ("TLS Version 1.0 Protocol Detection", "", 6.5, "Medium", "443",
     "The remote service accepts connections encrypted using TLS 1.0.",
     "Enable support for TLS 1.2 and 1.3, and disable TLS 1.0.", "false", 6),
    ("SSL Medium Strength Cipher Suites Supported (SWEET32)", "CVE-2016-2183", 7.5, "High", "443",
     "The remote host supports the use of 3DES / medium strength ciphers.",
     "Reconfigure the affected application to avoid use of medium strength ciphers.", "false", 5),
    ("SSL Certificate Cannot Be Trusted", "", 6.5, "Medium", "443",
     "The server's X.509 certificate cannot be trusted (self-signed).",
     "Purchase or generate a proper SSL certificate for this service.", "false", 3),
    ("SSL Certificate Expiry", "", 5.3, "Medium", "443",
     "The SSL certificate has already expired.",
     "Purchase or generate a new SSL certificate to replace the existing one.", "false", 2),
    ("SMB Signing not required", "", 5.3, "Medium", "445",
     "Signing is not required on the remote SMB server, allowing man-in-the-middle relay attacks.",
     "Enforce message signing in the host's configuration.", "false", 6),
    ("Missing HTTP Strict-Transport-Security Header", "", 4.3, "Medium", "443",
     "The remote web server is not enforcing HSTS.",
     "Configure the remote web server to use HSTS.", "false", 4),
    ("Web Server Directory Listing Enabled", "", 5.3, "Medium", "80",
     "Directory indexing is enabled on the web server, exposing file names.",
     "Disable directory listing in the web server configuration.", "false", 2),
    ("Linux Kernel Privilege Escalation (Dirty Pipe)", "CVE-2022-0847", 7.8, "High", "0",
     "The remote Linux kernel allows local privilege escalation via pipe buffers.",
     "Update the kernel to version 5.16.11, 5.15.25, 5.10.102 or later.", "true", 3),
    ("Microsoft Windows Security Update (KB5034441)", "CVE-2024-20666", 6.6, "Medium", "445",
     "The remote Windows host is missing a security update (BitLocker bypass).",
     "Apply security update KB5034441.", "false", 3),
    ("HTTP TRACE / TRACK Methods Allowed", "CVE-2003-1567", 5.3, "Medium", "80",
     "The remote web server supports the TRACE and/or TRACK methods.",
     "Disable these HTTP methods.", "false", 3),
    ("Web Server HTTP Header Information Disclosure", "", 0, "Low", "80",
     "The remote web server discloses its version in the Server header.",
     "Configure the server to hide version information in banners.", "false", 5),
    ("ICMP Timestamp Request Remote Date Disclosure", "CVE-1999-0524", 2.1, "Low", "0",
     "The remote host answers to an ICMP timestamp request.",
     "Filter out ICMP timestamp requests (13) and replies (14).", "false", 7),
    ("Nessus SYN scanner", "", 0, "None", "443",
     "It is possible to determine which TCP ports are open.",
     "Protect your target with an IP filter.", "false", 8),
    ("Telnet Server Detection", "", 6.5, "Medium", "23",
     "A Telnet server is listening on the remote port; credentials travel in cleartext.",
     "Disable Telnet and use SSH instead.", "false", 1),
    ("jQuery < 3.5.0 Multiple XSS", "CVE-2020-11022,CVE-2020-11023", 6.1, "Medium", "443",
     "The version of jQuery used by the web application is prior to 3.5.0.",
     "Upgrade jQuery to version 3.5.0 or later.", "false", 2),
]

rows = []
pid = 10000
for (name, cve, cvss, risk, port, syn, sol, exp, n) in VULNS:
    pid += random.randint(7, 900)
    for host, env in random.sample(HOSTS, n):
        rows.append({
            "Plugin ID": pid, "CVE": cve, "CVSS v3.0 Base Score": cvss if cvss else "",
            "Risk": risk, "Host": host, "Protocol": "tcp", "Port": port, "Name": name,
            "Synopsis": syn, "Solution": sol, "Exploit Available": exp, "Criticidad Activo": env,
        })
random.shuffle(rows)

os.makedirs(out, exist_ok=True)
with open(os.path.join(out, "ejemplo-vulnerabilidades.csv"), "w", newline="", encoding="utf-8") as f:
    w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
    w.writeheader(); w.writerows(rows)

try:
    from openpyxl import Workbook
    wb = Workbook(); ws = wb.active; ws.title = "Vulnerabilidades"
    ws.append(list(rows[0].keys()))
    for r in rows: ws.append(list(r.values()))
    wb.save(os.path.join(out, "ejemplo-vulnerabilidades.xlsx"))
except ImportError:
    print("openpyxl no instalado: solo se generó el CSV")
print(f"{len(rows)} hallazgos generados")
