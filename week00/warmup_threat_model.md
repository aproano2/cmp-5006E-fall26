# Week 0 Threat Model: Gmail (Warmup Exercise)

## 1. The System and Its Users
**The System:** Gmail is a cloud-based email service provided by Google that enables users to send, receive, organize, search, and manage electronic mail messages across web and mobile platforms.
**Primary Users:** Individual consumers, enterprise organizations, and third-party API integrations (clients).

---

## 2. System Sketch & Trust Boundaries

```
 +---------------------------------------------------------------+
 |                        PUBLIC INTERNET                        |
 |  [User / Browser] <---> [Google Front-End / TLS Termination]  |
 +-------------------------------|-------------------------------+
                                 | Trust Boundary 1 (Edge Proxy)
 +-------------------------------v-------------------------------+
 |                        GOOGLE INTERNAL NET                    |
 |  [Authentication (OAuth/2FA)]                                 |
 |  [Gmail Frontend / API Gateway]                               |
 |         |                                                     |
 |         v                                                     |
 |  [Spam/Phishing Classifiers & Security Scanners]              |
 |         |                                                     |
 |         v                                                     |
 |  [Core Storage & Indexing Cluster (Spanner / Bigtable)]        |
 +---------------------------------------------------------------+
```

---

## 3. Threat Model Table

| Threat / Scenario | Plausible Attack Vector | Impact | Mitigation Condition |
| :--- | :--- | :--- | :--- |
| **Credential Stuffing / Account Takeover** | An attacker uses stolen password credentials from a third-party data breach to log into a user's Gmail account via the web login page. | Full access to personal correspondence, password reset links for linked services, and contact lists. | **Condition:** Effective when multi-factor authentication (2FA/Passkeys) is enforced and suspicious login attempts from unknown locations or devices trigger automated step-up challenges. |
| **Malicious Attachment Delivery** | An attacker sends an email containing a disguised polymorphic malware executable or weaponized Office document to a user's inbox. | Compromise of the user's local endpoint device when the attachment is downloaded and opened. | **Condition:** Effective when automated email scanning engines analyze file signatures, sandbox attachments, and block known malicious payloads before they reach the inbox. |
| **Cross-Site Scripting (XSS) via HTML Email** | An attacker crafts a specially formatted HTML email designed to execute arbitrary JavaScript in the victim's browser context when viewed. | Session hijacking, unauthorized reading of email contents, or actions performed on behalf of the user within the Gmail web interface. | **Condition:** Effective when the web application strictly sanitizes incoming HTML/CSS, enforces a robust Content Security Policy (CSP), and renders emails inside isolated, sandboxed iframes. |
| **OAuth Token Hijacking** | An attacker tricks a user into authorizing a malicious third-party web application with broad scopes (`gmail.readonly`, `gmail.send`). | Continuous, covert exfiltration of incoming emails and capability to send phishing messages from the victim's address without needing their password. | **Condition:** Effective when users regularly audit authorized third-party applications, and Google enforces strict OAuth app verification requirements and scopes. |

---

## 4. Unknowns & Internal Visibility

**Unknown:** We could not determine from the outside the exact heuristic weights and machine learning architectures used by the automated spam, phishing, and malware classification pipelines to flag incoming messages. 
**Required Access:** To find out, we would need internal access to the source code, training datasets, and telemetry logs of Google's email filtering infrastructure and security classification microservices.