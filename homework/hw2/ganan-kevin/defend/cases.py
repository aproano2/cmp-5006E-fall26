"""Reproducible reflected-XSS corpus for B1 coverage and B2 regression."""
PART_A_XSS = "<script>alert(1)</script>"
XSS_ADDITIONAL = [
    "<ScRiPt>alert(2)</ScRiPt>",
    "<script type=text/javascript>alert(3)</script>",
    "<script>alert(document.domain)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "<body onload=alert(1)>",
    "<input autofocus onfocus=alert(1)>",
    "<details open ontoggle=alert(1)>open</details>",
    "<video><source onerror=alert(1)></video>",
    "<div onmouseover=alert(1)>move</div>",
    "<iframe src=javascript:alert(1)></iframe>",
    "<a href=javascript:alert(1)>click</a>",
    "<object data=javascript:alert(1)></object>",
    "<form action=javascript:alert(1)><input type=submit></form>",
    "<svg><a xlink:href=javascript:alert(1)>x</a></svg>",
    "<marquee onstart=alert(1)>scroll</marquee>",
]
XSS_BYPASSES = [
    {"id": "B1-XSS-01", "payload": "<a href=jav&#x61;script:alert(1)>click</a>"},
    {"id": "B1-XSS-02", "payload": "<a href=j&#97;vascript:alert(1)>click</a>"},
    {"id": "B1-XSS-03", "payload": "<a href=java&#x73;cript:alert(1)>click</a>"},
]
