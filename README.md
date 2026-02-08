# Project_1
Audit Tool
Overview
This project is an interactive network and system security audit tool. It enables users to perform deep security audits on their own machine or on remote (authorized) systems by scanning open ports, checking firewall status, and listing active system processes. The tool outputs interactive HTML and PDF reports with a risk score and actionable security recommendations.

Features
Local System Audit: Scans all open ports on the local device, verifies Windows firewall status, lists running processes, and calculates a composite security risk score.

Remote Audit: Scans open ports on a specified remote machine (authorized targets only), with options for fast (common ports) or full (1–65535 ports) scanning.

Reports: Generates detailed, interactive HTML and professionally formatted PDF audit reports, documenting findings, risks, and guidance on closing risky ports (Windows only).

Risk Analysis: Highlights critical and medium-risk open ports and lowers the security score if the firewall is off.

Cross-Platform: Supports most functionality on Windows and Linux, but firewall checks and port-blocking guidance are tailored for Windows systems.

Dependencies
Before running, ensure the following Python libraries are installed:

psutil

reportlab

Also, Nmap must be installed and callable from the command line for port scanning.

Install dependencies with:

bash
pip install psutil reportlab
For Nmap, download and install from: https://nmap.org/download.html

Usage
Run the script from the command line:

bash
python audit.py
Choose one of the options:

Local System Audit: Perform a full interactive audit of the local system.

Remote Audit (Fast, common ports): Scan a remote host for common open ports.

Remote Audit (Full, all ports): Scan a remote host for all 65535 ports.

Example
text
ReconX Security Audit Interactive Reports
1 Local System Audit FULL interactive
2 Remote Audit FAST common ports
3 Remote Audit FULL 1-65535 ports

Select (1/2/3): 1
Reports will be generated as HTML and PDF in the current directory.

Output
auditreportlocal.html and auditreportlocal.pdf for local audits.

auditreportremote.html or auditreportremotefull.html (and corresponding PDF) for remote audits.

Security & Legal Note
This tool is for authorized security testing only. Unauthorized scanning of remote systems may violate organizational policies or laws.
