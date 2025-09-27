import socket
import platform
import datetime
import subprocess
import psutil
import html
import re
import sys
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors

# ============ Config ============
DEBUG_PRINT = False
FAST_PORTS = "21,22,23,25,53,80,110,135,139,143,443,445,3306,3389,8080"
CRITICAL_PORTS = [21,22,23,25,135,139,445,1433,1521,3306,3389]
MEDIUM_PORTS   = [53,80,110,143,443,8080]
# ================================

# ---------- Helpers / OS checks ----------
def is_windows():
    return platform.system().lower() == "windows"

def shell_run(args):
    try:
        return subprocess.check_output(args, text=True, stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as e:
        return e.output or f"ERROR: {e}"
    except FileNotFoundError:
        return "ERROR: Command not found (is it installed and in PATH?)."
    except Exception as e:
        return f"ERROR: {e}"

# ---------- Firewall (Windows) ----------
def get_firewall_status():
    if not is_windows():
        return "Firewall status fetching supported on Windows only."
    try:
        return subprocess.check_output(
            'netsh advfirewall show allprofiles', shell=True, text=True
        )
    except Exception as e:
        return f"Error checking firewall: {e}"

def get_blocked_ports():
    if not is_windows():
        return []
    blocked_ports = []
    try:
        output = subprocess.check_output(
            'netsh advfirewall firewall show rule name=all',
            shell=True, text=True
        )
        current_port = None
        for line in output.splitlines():
            s = line.strip()
            if s.lower().startswith("localport"):
                port_info = s.split(":", 1)[-1].strip()
                if port_info.isdigit():
                    current_port = int(port_info)
            elif s.lower().startswith("action"):
                action = s.split(":", 1)[-1].strip().lower()
                if action == "block" and current_port:
                    blocked_ports.append(current_port)
                    current_port = None
        return blocked_ports
    except Exception:
        return []

# ---------- Nmap scanning ----------
def run_nmap(target: str, full: bool, skip_discovery=True, service_detect=True) -> str:
    """
    full=True  -> scan all ports (1-65535)
    full=False -> scan FAST_PORTS
    """
    args = ["nmap"]
    # Speed up
    args += ["-T4"]
    if skip_discovery:
        args += ["-Pn"]
    if service_detect:
        args += ["-sV"]

    if full:
        args += ["-p-"]
    else:
        args += ["-p", FAST_PORTS]

    args.append(target)

    if DEBUG_PRINT:
        print("Running:", " ".join(args))
    return shell_run(args)

# ---------- Parse Nmap ----------
def parse_nmap(output: str):
    """
    Returns rows: list of dicts:
    {port: 445, proto: 'tcp', state: 'open', service: 'microsoft-ds', extra: '...' }
    """
    rows = []
    for line in output.splitlines():
        if re.match(r"^\d+/(tcp|udp)\s+", line):
            # Example: "445/tcp  open  microsoft-ds  syn-ack"
            parts = re.split(r"\s+", line.strip())
            if len(parts) >= 3:
                port_proto = parts[0]               # "445/tcp"
                state      = parts[1]               # "open"
                service    = parts[2]               # "microsoft-ds" (maybe "-")
                extra      = " ".join(parts[3:]) if len(parts) > 3 else ""
                port = int(port_proto.split("/")[0])
                proto = port_proto.split("/")[1]
                rows.append({
                    "port": port,
                    "proto": proto,
                    "state": state,
                    "service": service,
                    "extra": extra
                })
    return rows

# ---------- Processes ----------
def get_processes():
    plist = []
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            info = proc.info
            name = info.get('name') or "Unknown"
            plist.append({"pid": info['pid'], "name": name})
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    # stable order
    return sorted(plist, key=lambda x: x["pid"])

# ---------- Risk scoring ----------
def compute_score_and_risks(open_rows, firewall_text=None):
    score = 10
    risks = []

    # firewall impact (Windows only)
    if firewall_text and "State                                 OFF" in firewall_text:
        score -= 3
        risks.append("Firewall profile(s) OFF")

    for r in open_rows:
        p = r["port"]
        if r["state"] != "open":
            continue
        if p in CRITICAL_PORTS:
            score -= 2
            risks.append(f"Critical port open: {p} ({r['service']})")
        elif p in MEDIUM_PORTS:
            score -= 1
            risks.append(f"Medium risk port open: {p} ({r['service']})")

    score = max(score, 0)
    if score >= 8:
        status = "🟢 Secure"; badge = "score-green"
    elif score >= 5:
        status = "🟡 Moderate"; badge = "score-yellow"
    else:
        status = "🔴 Risky"; badge = "score-red"

    return score, status, badge, risks

# ---------- PDF export ----------
def export_pdf(summary, open_rows_text, firewall=None, processes=None, filename="audit_report.pdf"):
    doc = SimpleDocTemplate(filename)
    styles = getSampleStyleSheet()
    elements = []

    elements.append(Paragraph("Security Audit Report", styles['Title']))
    elements.append(Spacer(1, 10))

    for k, v in summary.items():
        elements.append(Paragraph(f"<b>{html.escape(str(k))}:</b> {html.escape(str(v))}", styles["Normal"]))

    elements.append(Spacer(1, 10))
    elements.append(Paragraph("<b>Open Ports</b>", styles["Heading2"]))
    elements.append(Paragraph(html.escape(open_rows_text).replace("\n","<br/>"), styles["Code"]))

    if firewall:
        elements.append(Spacer(1, 10))
        elements.append(Paragraph("<b>Firewall Status</b>", styles["Heading2"]))
        elements.append(Paragraph(html.escape(firewall).replace("\n","<br/>"), styles["Code"]))

    if processes:
        elements.append(Spacer(1, 10))
        elements.append(Paragraph("<b>Processes</b>", styles["Heading2"]))
        table_data = [["PID", "Name"]] + [[str(p['pid']), p['name']] for p in processes]
        table = Table(table_data, repeatRows=1)
        table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#30475e")),
            ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0,0), (-1,0), 10),
            ('ALIGN', (0,0), (-1,-1), 'LEFT'),
            ('GRID', (0,0), (-1,-1), 0.25, colors.grey),
        ]))
        elements.append(table)

    doc.build(elements)
    print(f"✅ PDF Exported: {filename}")

# ---------- HTML (interactive) ----------
def build_interactive_html(title, summary_pairs, score, status, badge, risks, open_rows, raw_ports_text=None, firewall_text=None, processes=None, pdf_file=None, howto_close_ports=False):
    # table rows for open ports
    open_rows_sorted = sorted([r for r in open_rows if r["state"] == "open"], key=lambda x: (x["proto"], x["port"]))
    ports_table = "".join([
        f"<tr><td>{r['port']}/{r['proto']}</td><td>{html.escape(r['service'])}</td><td>{html.escape(r['extra'])}</td></tr>"
        for r in open_rows_sorted
    ]) or "<tr><td colspan='3'>No open ports found.</td></tr>"

    risks_html = "<ul>" + "".join([f"<li>{html.escape(x)}</li>" for x in risks]) + "</ul>" if risks else "No major risks detected."

    proc_rows = ""
    if processes:
        proc_rows = "".join([f"<tr><td>{p['pid']}</td><td>{html.escape(p['name'])}</td></tr>" for p in processes])

    # CSS + HTML
    html_doc = f"""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<title>{html.escape(title)}</title>
<style>
  body {{
    font-family: 'Segoe UI', system-ui, -apple-system, Arial, sans-serif;
    background: #f4f6f9;
    margin: 24px;
    color: #2d3345;
  }}
  .container {{
    max-width: 1000px;
    margin: 0 auto;
  }}
  h1,h2,h3 {{ margin: 0 0 10px; }}
  .card {{
    background: #fff;
    border-radius: 14px;
    box-shadow: 0 6px 20px rgba(0,0,0,0.08);
    padding: 18px 20px;
    margin-bottom: 18px;
  }}
  .summary p {{ margin: 6px 0; }}
  .badge {{
    display: inline-block; padding: 6px 12px; border-radius: 12px;
    color: #fff; font-weight: 600;
  }}
  .score-green {{ background:#28a745; }}
  .score-yellow {{ background:#ffc107; color:#1a1a1a; }}
  .score-red {{ background:#dc3545; }}

  details {{
    background: #fff; border-radius: 14px; box-shadow: 0 6px 20px rgba(0,0,0,0.08);
    padding: 14px 16px; margin-bottom: 14px;
  }}
  summary {{
    font-weight: 600; cursor: pointer; outline: none;
  }}
  table {{
    width: 100%; border-collapse: collapse; margin-top: 10px;
  }}
  th, td {{
    padding: 10px 12px; border-bottom: 1px solid #e8ebf2; text-align: left;
  }}
  th {{
    background: #30475e; color: #fff; position: sticky; top: 0;
  }}
  tr:hover {{ background: #f9fbff; }}
  .note {{
    background: #fff3cd; border-left: 6px solid #ffc107;
    padding: 10px 12px; border-radius: 8px; margin-top: 10px;
    font-size: 14px;
  }}
  .links a {{ text-decoration: none; }}
</style>
</head>
<body>
<div class="container">
  <div class="card summary">
    <h1>{html.escape(title)}</h1>
    {"".join([f"<p><b>{html.escape(k)}:</b> {html.escape(str(v))}</p>" for k,v in summary_pairs])}
    <p><b>Security Score:</b> <span class="badge {badge}">{score}/10 — {status}</span></p>
    {"<p class='links'><a href='"+html.escape(pdf_file)+"' target='_blank'>📄 Download PDF</a></p>" if pdf_file else ""}
  </div>

  <div class="card">
    <h2>⚠️ Risks Identified</h2>
    {risks_html}
  </div>

  <details open>
    <summary>📡 Open Ports</summary>
    <table>
      <thead><tr><th>Port/Proto</th><th>Service</th><th>Details</th></tr></thead>
      <tbody>{ports_table}</tbody>
    </table>
    {"<div class='note'><b>Raw nmap output:</b><br><pre>"+html.escape(raw_ports_text)+"</pre></div>" if raw_ports_text else ""}
  </details>

  {f"""
  <details>
    <summary>🛡 Firewall Status (Local)</summary>
    <pre>{html.escape(firewall_text)}</pre>
  </details>
  """ if firewall_text else ""}

  {f"""
  <details>
    <summary>⚙ Running Processes ({len(processes)} total)</summary>
    <table>
      <thead><tr><th>PID</th><th>Name</th></tr></thead>
      <tbody>{proc_rows}</tbody>
    </table>
  </details>
  """ if processes else ""}

  {f"""
  <details>
    <summary>📖 How to Close Risky Ports (Windows Firewall)</summary>
    <ol>
      <li>Press <b>Win + R</b> → type <code>wf.msc</code> → Enter.</li>
      <li><b>Inbound Rules → New Rule → Port</b>.</li>
      <li>Select <b>TCP</b>, enter port number (e.g., 135).</li>
      <li>Choose <b>Block the connection</b> → apply to <b>Domain/Private/Public</b>.</li>
      <li>Name it (e.g., <i>Block 135</i>) → Finish.</li>
      <li>Verify: <code>Test-NetConnection -ComputerName localhost -Port 135</code></li>
    </ol>
    <p class="note">Avoid blocking essential ports like 80/443 unless you know the impact.</p>
  </details>
  """ if howto_close_ports else ""}

  <div class="note">
    <b>Note:</b> This tool is for <u>authorized security testing</u> only.
    Unauthorized scanning may violate policy or law.
  </div>
</div>
</body>
</html>
"""
    return html_doc

# ---------- Local audit (full + interactive) ----------
def local_audit():
    hostname = socket.gethostname()
    ip = socket.gethostbyname(hostname)
    os_info = platform.platform()
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Full scan on local IP (only open ports shown)
    raw_ports = run_nmap(ip, full=True)
    rows = parse_nmap(raw_ports)
    open_rows = [r for r in rows if r["state"] == "open"]

    # Firewall + processes (Windows firewall only)
    fw_text = get_firewall_status()
    blocked = get_blocked_ports() if is_windows() else []

    # Score based on open ports (+ firewall OFF impact)
    score, status, badge, risks = compute_score_and_risks(open_rows, firewall_text=fw_text)

    # Summary for PDF
    summary = {
        "Date & Time": now,
        "Hostname": hostname,
        "IP Address": ip,
        "Operating System": os_info,
        "Open Ports Count": len(open_rows),
        "Security Score": f"{score}/10 — {status}",
    }

    # Processes
    procs = get_processes()

    # Prepare open ports text for PDF (clean)
    open_ports_text = "\n".join([f"{r['port']}/{r['proto']}  open  {r['service']}  {r['extra']}" for r in open_rows]) or "No open ports found."

    # Exclude ports that are explicitly blocked by firewall (display purpose only)
    # (We still show 'open', but you can choose to filter if needed)
    # Keeping as-is to reflect actual nmap results.

    # Export PDF
    pdf_file = "audit_report_local.pdf"
    export_pdf(summary, open_ports_text, firewall=fw_text, processes=procs, filename=pdf_file)

    # Build interactive HTML
    html_report = build_interactive_html(
        title="🔒 Local Security Audit Report",
        summary_pairs=[("Date & Time", now), ("Hostname", hostname), ("IP Address", ip), ("Operating System", os_info)],
        score=score, status=status, badge=badge,
        risks=risks,
        open_rows=open_rows,
        raw_ports_text=raw_ports,
        firewall_text=fw_text,
        processes=procs,
        pdf_file=pdf_file,
        howto_close_ports=is_windows()  # show guide on Windows
    )

    with open("audit_report_local.html", "w", encoding="utf-8") as f:
        f.write(html_report)

    print("✅ Local report saved: audit_report_local.html")
    print("✅ Local PDF saved: audit_report_local.pdf")

# ---------- Remote audit (fast/full + interactive) ----------
def remote_audit(full=False):
    target_in = input("Enter IP/Domain to audit (authorized targets only): ").strip()
    if not target_in:
        print("❌ No target provided.")
        return
    target = target_in.replace("http://","").replace("https://","").strip("/")
    try:
        resolved_ip = socket.gethostbyname(target)
    except Exception:
        resolved_ip = "Unknown"

    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    raw_ports = run_nmap(target, full=full)
    rows = parse_nmap(raw_ports)
    open_rows = [r for r in rows if r["state"] == "open"]

    # Score only from open ports (no remote firewall/process)
    score, status, badge, risks = compute_score_and_risks(open_rows, firewall_text=None)

    summary = {
        "Date & Time": now,
        "Target": target,
        "Resolved IP": resolved_ip,
        "Scan Type": "FULL (1–65535)" if full else "FAST (common)",
        "Open Ports Count": len(open_rows),
        "Security Score": f"{score}/10 — {status}",
    }

    # PDF
    pdf_file = "audit_report_remote_full.pdf" if full else "audit_report_remote.pdf"
    open_ports_text = "\n".join([f"{r['port']}/{r['proto']}  open  {r['service']}  {r['extra']}" for r in open_rows]) or "No open ports found."
    export_pdf(summary, open_ports_text, firewall=None, processes=None, filename=pdf_file)

    # HTML
    html_file = "audit_report_remote_full.html" if full else "audit_report_remote.html"
    html_report = build_interactive_html(
        title="🌐 Remote Security Audit Report",
        summary_pairs=[("Date & Time", now), ("Target", target), ("Resolved IP", resolved_ip), ("Scan Type", "FULL (1–65535)" if full else "FAST (common)")],
        score=score, status=status, badge=badge,
        risks=risks,
        open_rows=open_rows,
        raw_ports_text=raw_ports,
        firewall_text=None,
        processes=None,
        pdf_file=pdf_file,
        howto_close_ports=False
    )
    with open(html_file, "w", encoding="utf-8") as f:
        f.write(html_report)

    print(f"✅ Remote report saved: {html_file}")
    print(f"✅ Remote PDF saved: {pdf_file}")

# ---------- Main ----------
def main():
    print("=== ReconX Security Audit (Interactive Reports) ===")
    print("1) Local System Audit (FULL + interactive)")
    print("2) Remote Audit (FAST — common ports)")
    print("3) Remote Audit (FULL — 1–65535 ports)")
    choice = input("Select (1/2/3): ").strip()

    if choice == "3":
        remote_audit(full=True)
    elif choice == "2":
        remote_audit(full=False)
    else:
        local_audit()

if __name__ == "__main__":
    # quick nmap existence hint
    try:
        _ = subprocess.check_output(["nmap", "-V"], text=True)
    except Exception:
        print("⚠️ Nmap not found. Please install Nmap and ensure it's in PATH.")
    main()
