"""
analyzer.py - URL analysis, cross-checking and report building
(DEMONSTRATION MODE: rule-based, not a trained machine-learning model)

The code NEVER visits the submitted URL. It only studies the text of the URL.
To upgrade the project, replace the rules in analyze_url() with a trained
classifier and replace analyze_context() with a real multimodal fusion method.
"""
import ipaddress
import re
from datetime import datetime
from urllib.parse import urlsplit

# ----------------------------------------------------------------- settings
BRANDS = {
    "paypal":    {"name": "PayPal",    "keywords": ["paypal"],            "domains": ["paypal.com"]},
    "google":    {"name": "Google",    "keywords": ["google", "gmail"],   "domains": ["google.com", "gmail.com", "youtube.com"]},
    "microsoft": {"name": "Microsoft", "keywords": ["microsoft", "office365", "outlook"], "domains": ["microsoft.com", "live.com", "office.com", "microsoftonline.com", "outlook.com"]},
    "amazon":    {"name": "Amazon",    "keywords": ["amazon"],            "domains": ["amazon.com", "amazon.in"]},
    "apple":     {"name": "Apple",     "keywords": ["apple", "icloud"],   "domains": ["apple.com", "icloud.com"]},
    "netflix":   {"name": "Netflix",   "keywords": ["netflix"],           "domains": ["netflix.com"]},
    "facebook":  {"name": "Facebook",  "keywords": ["facebook"],          "domains": ["facebook.com", "fb.com"]},
    "instagram": {"name": "Instagram", "keywords": ["instagram"],         "domains": ["instagram.com"]},
    "whatsapp":  {"name": "WhatsApp",  "keywords": ["whatsapp"],          "domains": ["whatsapp.com"]},
    "sbi":       {"name": "SBI (State Bank of India)", "keywords": ["sbi", "onlinesbi"], "domains": ["sbi.co.in", "onlinesbi.sbi"]},
    "hdfc":      {"name": "HDFC Bank", "keywords": ["hdfc", "hdfcbank"],  "domains": ["hdfcbank.com"]},
    "icici":     {"name": "ICICI Bank","keywords": ["icici", "icicibank"],"domains": ["icicibank.com"]},
    "paytm":     {"name": "Paytm",     "keywords": ["paytm"],             "domains": ["paytm.com"]},
    "flipkart":  {"name": "Flipkart",  "keywords": ["flipkart"],          "domains": ["flipkart.com"]},
}

SUSPICIOUS_TLDS = {"xyz", "top", "tk", "click", "zip", "gq", "ml", "cf", "ga", "work", "loan", "country", "support"}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "rb.gy", "ow.ly", "shorturl.at"}
URL_KEYWORDS = ["login", "signin", "verify", "secure", "update", "account", "confirm", "banking", "password", "wallet", "suspend"]
URGENT_PHRASES = ["urgent", "suspended", "immediately", "verify your", "limited access", "locked", "expire", "unusual activity", "action required", "within 24 hours"]
CREDENTIAL_PHRASES = ["password", "otp", "card number", "cvv", "pin", "net banking", "debit card", "aadhaar"]
SECOND_LEVEL = {"co.uk", "org.uk", "co.in", "ac.in", "gov.in", "org.in", "net.in", "bank.in", "com.au", "co.jp", "com.br"}
LEET = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})


# ---------------------------------------------------------------- utilities
def normalize_url(raw):
    """Validate user input. Returns (url, scheme_was_assumed). Raises ValueError."""
    raw = (raw or "").strip()
    if not raw:
        raise ValueError("Please enter a website URL.")
    if len(raw) > 2000:
        raise ValueError("The URL is too long (maximum 2000 characters).")
    if re.search(r"\s", raw):
        raise ValueError("The URL must not contain spaces.")

    assumed = False
    if "://" in raw:
        if raw.split("://", 1)[0].lower() not in ("http", "https"):
            raise ValueError("Only http:// and https:// URLs can be analysed.")
        url = raw
    else:
        if re.match(r"^(javascript|data|file|mailto|vbscript):", raw, re.I):
            raise ValueError("Only http:// and https:// URLs can be analysed.")
        url, assumed = "https://" + raw, True

    parts = urlsplit(url)
    try:
        parts.port                                  # raises ValueError if the port is invalid
    except ValueError:
        raise ValueError("The URL contains an invalid port number.")
    host = parts.hostname
    if not host:
        raise ValueError("The URL does not contain a valid website address.")
    try:
        host_ascii = host.encode("idna").decode("ascii")
    except UnicodeError:
        raise ValueError("The domain name contains invalid characters.")
    if not _is_ip_like(host_ascii) and not re.fullmatch(
            r"(?=.{1,253}$)([a-z0-9-]{1,63}\.)+[a-z0-9-]{2,63}", host_ascii.lower()):
        raise ValueError("Please enter a valid domain name such as example.com.")
    return url, assumed


def _is_ip_like(host):
    if host.isdigit():
        return True
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def registrable_domain(host):
    """Approximate the main domain (example.co.in from login.example.co.in)."""
    if _is_ip_like(host):
        return host
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    last_two = ".".join(labels[-2:])
    return ".".join(labels[-3:]) if last_two in SECOND_LEVEL else last_two


def detect_brand(host, registrable, path):
    """Look for a well-known brand name inside the URL text."""
    text = (host + " " + path).lower()
    tokens = [t for t in re.split(r"[^a-z0-9]+", text) if t]
    leet_tokens = [t.translate(LEET).replace("rn", "m").replace("vv", "w") for t in tokens]

    def hit(token_list, keywords):
        return any(t == k or (len(k) >= 5 and k in t) for t in token_list for k in keywords)

    for info in BRANDS.values():
        plain, leet = hit(tokens, info["keywords"]), hit(leet_tokens, info["keywords"])
        if plain or leet:
            if registrable in info["domains"]:
                return {"brand": info["name"], "kind": "official", "official": info["domains"][0]}
            return {"brand": info["name"], "kind": "keyword" if plain else "lookalike",
                    "official": info["domains"][0]}
    return None


# --------------------------------------------------------------- URL analysis
def analyze_url(url, scheme_assumed=False):
    parts = urlsplit(url)
    host = parts.hostname.encode("idna").decode("ascii").lower()
    path = (parts.path or "") + (("?" + parts.query) if parts.query else "")
    reg = registrable_domain(host)
    is_ip = _is_ip_like(host)
    feats = []

    def add(label, value, flagged, points, note):
        feats.append({"label": label, "value": value, "flagged": flagged,
                      "points": points if flagged else 0, "note": note})

    # 1. Connection security
    scheme = parts.scheme.lower()
    if scheme_assumed:
        add("Connection (HTTPS)", "Not specified", False, 0, "No scheme was typed, so HTTPS was assumed for the analysis.")
    elif scheme == "https":
        add("Connection (HTTPS)", "HTTPS", False, 0, "HTTPS is used. Note that phishing sites can use HTTPS too, so this alone proves nothing.")
    else:
        add("Connection (HTTPS)", "HTTP", True, 15, "The page is not encrypted, which is unusual for a login or payment page.")

    # 2. Host type
    add("IP address as host", "Yes" if is_ip else "No", is_ip, 30,
        "Real services almost never use a raw IP address in their links." if is_ip else "A normal domain name is used.")

    # 3. '@' trick
    at = "@" in url.split("//", 1)[-1].split("/", 1)[0]
    add("'@' symbol in address", "Yes" if at else "No", at, 20,
        "Text before '@' is ignored by the browser and can hide the real destination." if at else "No '@' trick found.")

    # 4. Length
    n = len(url)
    add("URL length", f"{n} characters", n > 54, 10 if n > 75 else 5,
        "Very long URLs are often used to hide the real domain." if n > 54 else "The length is normal.")

    # 5. Subdomains
    sub_count = 0 if is_ip else len(host.split(".")) - len(reg.split("."))
    add("Number of subdomains", str(sub_count), sub_count >= 3, 12,
        "Many subdomains can be used to make a fake address look official." if sub_count >= 3 else "The number of subdomains is normal.")

    # 6. Hyphens
    hy = host.count("-")
    add("Hyphens in domain", str(hy), hy >= 2, 10,
        "Several hyphens (like secure-login-bank.com) are common in fake domains." if hy >= 2 else "No unusual hyphen use.")

    # 7. Punycode / non-ASCII
    puny = "xn--" in host
    add("Look-alike (international) characters", "Yes" if puny else "No", puny, 20,
        "The domain uses international characters that can imitate real letters." if puny else "No look-alike characters.")

    # 8. TLD
    tld = host.rsplit(".", 1)[-1] if not is_ip else ""
    add("Top-level domain", "." + tld if tld else "n/a", tld in SUSPICIOUS_TLDS, 15,
        f".{tld} is frequently abused in phishing campaigns." if tld in SUSPICIOUS_TLDS else "The top-level domain is not on the watch list.")

    # 9. Keywords
    low = url.lower()
    found = [k for k in URL_KEYWORDS if k in low]
    add("Sensitive keywords in URL", ", ".join(found) if found else "None", len(found) >= 1,
        12 if len(found) >= 2 else 6,
        "Words such as login or verify are used to look trustworthy." if found else "No sensitive keywords found.")

    # 10. Shortener
    short = reg in SHORTENERS
    add("URL shortener", "Yes" if short else "No", short, 15,
        "A shortener hides the final destination." if short else "No shortening service used.")

    # 11. Port
    port = parts.port
    odd_port = port not in (None, 80, 443)
    add("Port number", str(port) if port else "Default", odd_port, 10,
        "A non-standard port is unusual for public websites." if odd_port else "Standard port.")

    # 12. Digits in host
    digits = sum(c.isdigit() for c in host)
    ratio = digits / max(len(host), 1)
    add("Digits in domain", f"{digits} ({round(ratio * 100)}%)", (not is_ip) and ratio > 0.3, 8,
        "A high share of digits looks machine-generated." if (not is_ip) and ratio > 0.3 else "Normal digit usage.")

    # 13. Encoding / redirects
    enc = low.count("%") > 3 or "//" in path
    add("Encoded characters or double slashes", "Yes" if enc else "No", enc, 5,
        "Heavy encoding or '//' in the path can disguise redirects." if enc else "None found.")

    # 14. Brand impersonation
    brand = detect_brand(host, reg, path)
    if brand and brand["kind"] != "official":
        what = "a look-alike spelling of" if brand["kind"] == "lookalike" else "the name of"
        add("Brand impersonation", brand["brand"], True, 35,
            f"The URL contains {what} {brand['brand']}, but the real domain is {brand['official']}, not {reg}.")
    elif brand:
        add("Brand impersonation", brand["brand"], False, 0, f"The domain {reg} belongs to {brand['brand']}.")
    else:
        add("Brand impersonation", "None detected", False, 0, "No well-known brand name was found in the URL.")

    score = min(100, sum(f["points"] for f in feats))
    return {"host": host, "registrable": reg, "scheme": scheme, "features": feats,
            "score": score, "brand": brand, "is_ip": is_ip}


# -------------------------------------------- cross-checking (text + visual)
def analyze_context(url_info, claimed_brand, page_text):
    """Compare what the user saw (brand logo, page text) with the URL."""
    findings, items = [], []
    reg = url_info["registrable"]

    if claimed_brand in BRANDS:
        info = BRANDS[claimed_brand]
        if reg in info["domains"]:
            findings.append({"level": "ok", "text": f"The brand shown in the screenshot ({info['name']}) matches the domain {reg}."})
        else:
            findings.append({"level": "warn", "text": f"The screenshot shows the {info['name']} brand, but the website is hosted on {reg}, not on an official {info['name']} domain ({info['domains'][0]}). This brand-versus-domain mismatch is a classic phishing sign."})
            items.append({"source": "Cross-check", "label": f"{info['name']} brand does not match domain", "points": 30})

    text = (page_text or "").lower()
    if text.strip():
        urgent = [p for p in URGENT_PHRASES if p in text]
        cred = [p for p in CREDENTIAL_PHRASES if p in text]
        if urgent:
            pts = min(12, 4 * len(urgent))
            findings.append({"level": "warn", "text": "Pressure or urgency wording found in the page text: " + ", ".join(urgent) + "."})
            items.append({"source": "Page text", "label": "Urgency language", "points": pts})
        if cred:
            pts = min(10, 5 * len(cred))
            findings.append({"level": "warn", "text": "The page text asks for sensitive information: " + ", ".join(cred) + "."})
            items.append({"source": "Page text", "label": "Requests sensitive details", "points": pts})
        if not urgent and not cred:
            findings.append({"level": "info", "text": "No urgency wording or credential requests were found in the supplied page text."})
    return findings, items


# ------------------------------------------------------------ report builder
def _category(score):
    return "Low" if score < 25 else ("Medium" if score < 55 else "High")


def build_report(scan_id, url, scheme_assumed, claimed_brand, page_text, image_filename, image_info):
    ua = analyze_url(url, scheme_assumed)
    findings, ctx_items = analyze_context(ua, claimed_brand, page_text)

    breakdown = [{"source": "URL analysis", "label": f["label"], "points": f["points"]}
                 for f in ua["features"] if f["points"] > 0] + ctx_items
    score = min(100, sum(b["points"] for b in breakdown))
    category = _category(score)

    top = sorted(breakdown, key=lambda b: -b["points"])[:5]
    reasons = [f"{b['label']} (+{b['points']} points)" for b in top] or \
              ["No strong risk indicators were found in the information provided."]

    summaries = {
        "High": "Several strong phishing indicators were detected. Treat this website as dangerous and do not enter any personal information.",
        "Medium": "Some suspicious characteristics were found. Verify this website through an official channel before trusting it.",
        "Low": "Few risk indicators were found by this limited analysis. This does NOT prove that the website is safe.",
    }

    precautions = {
        "High": ["Do not open the link or enter passwords, OTPs or card details.",
                 "If you already entered details, change that password immediately and contact your bank or service provider.",
                 "Report the site, for example on the National Cyber Crime Reporting Portal (cybercrime.gov.in) in India."],
        "Medium": ["Do not enter sensitive information until you have verified the site.",
                   "Open the official website by typing its address yourself instead of using this link.",
                   "Ask the sender through a different channel whether they really sent the link."],
        "Low": ["Stay alert: a low score is not a guarantee of safety.",
                "Check that the domain spelling exactly matches the official site.",
                "Be careful with any request for passwords, OTPs or payments."],
    }

    brand_ind = []
    if ua["brand"] and ua["brand"]["kind"] != "official":
        brand_ind.append(f"URL text suggests {ua['brand']['brand']}, but the domain is {ua['registrable']}.")
    elif ua["brand"]:
        brand_ind.append(f"The URL belongs to the official {ua['brand']['brand']} domain.")
    if claimed_brand in BRANDS and claimed_brand and image_filename:
        brand_ind.append(f"Brand reported from the screenshot: {BRANDS[claimed_brand]['name']} (entered by the user, not detected by AI).")
    if not brand_ind:
        brand_ind.append("No brand impersonation indicators were found.")

    vlm_on = bool(image_info and image_info["vlm_connected"])

    return {
        "scan": {"id": scan_id, "url": url,
                 "created": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                 "status": "Completed",
                 "mode": "Demonstration mode (rule-based analysis, no trained model)",
                 "scheme_assumed": scheme_assumed},
        "overall": {"score": score, "category": category,
                    "confidence": "Not available. The score comes from simple rules and is not a calibrated probability.",
                    "summary": summaries[category], "reasons": reasons},
        "url_analysis": {"host": ua["host"], "registrable": ua["registrable"], "features": ua["features"],
                         "suspicious": [f for f in ua["features"] if f["flagged"]]},
        "visual": {"submitted": bool(image_filename), "filename": image_filename, "info": image_info,
                   "brand_indicators": brand_ind, "vlm_connected": vlm_on},
        "vl": {"findings": findings,
               "context_given": bool(claimed_brand or (page_text or "").strip()),
               "limitations": [
                   "No vision-language model is connected, so logos, login forms and page layout were not detected automatically.",
                   "The website was never opened. Domain age, DNS records, certificates and reputation databases were not checked.",
                   "Brand and page text come from what the user typed, not from automatic extraction.",
                   "Rule-based scores can produce false alarms and can miss new attack styles."]},
        "final": {"score": score, "category": category, "breakdown": breakdown,
                  "reasons": reasons, "precautions": precautions[category]},
        "recommendations": [
            "Type the official address into your browser instead of clicking links in messages.",
            "HTTPS (the padlock) only means the connection is encrypted. It does not mean the site is trustworthy.",
            "Never share OTPs, PINs or passwords with anyone, even if the message looks urgent.",
            "Use a password manager and turn on two-factor authentication where possible.",
            "Keep your browser and operating system up to date.",
            "When in doubt, contact the organisation using the phone number or app from its official website.",
        ],
    }