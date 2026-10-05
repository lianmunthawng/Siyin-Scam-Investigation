import socket
import ssl
import urllib.request
import urllib.parse
import re
import subprocess
from datetime import datetime, timezone

def server_info(ip):
    import json
    import urllib.request

    try:
        url = f"https://ipwho.is/{ip}"
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "Siyin-Link-Checker/12"}
        )

        with urllib.request.urlopen(req, timeout=10) as response:
            data = json.loads(response.read().decode())

        if not data.get("success"):
            return None

        connection = data.get("connection", {})

        return {
            "ip": data.get("ip"),
            "country": data.get("country"),
            "region": data.get("region"),
            "city": data.get("city"),
            "isp": connection.get("isp"),
            "org": connection.get("org"),
            "asn": connection.get("asn")
        }

    except Exception as e:
        return {"error": str(e)}


def virustotal_domain_check(domain):
    import os
    import json

    api_key = os.environ.get("VT_API_KEY")

    if not api_key:
        return None

    try:
        req = urllib.request.Request(
            f"https://www.virustotal.com/api/v3/domains/{urllib.parse.quote(domain)}",
            headers={
                "x-apikey": api_key,
                "User-Agent": "Siyin-Link-Checker/11"
            }
        )

        with urllib.request.urlopen(req, timeout=15) as response:
            data = json.loads(response.read().decode())

        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        results = attrs.get("last_analysis_results", {})

        categories = {
            "malware": 0,
            "phishing": 0,
            "trojan": 0,
            "ransomware": 0
        }

        detections = []

        for engine, result in results.items():
            category = str(result.get("category", "")).lower()
            result_name = str(result.get("result", "") or "").lower()

            combined = f"{category} {result_name}"

            if category in ("malicious", "suspicious"):
                detections.append({
                    "engine": engine,
                    "category": category,
                    "result": result.get("result")
                })

            if "ransomware" in combined:
                categories["ransomware"] += 1
            elif "trojan" in combined:
                categories["trojan"] += 1
            elif "phish" in combined:
                categories["phishing"] += 1
            elif "malware" in combined or "virus" in combined:
                categories["malware"] += 1

        return {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "reputation": attrs.get("reputation", 0),
            "malware": categories["malware"],
            "phishing": categories["phishing"],
            "trojan": categories["trojan"],
            "ransomware": categories["ransomware"],
            "detections": detections
        }

    except Exception as e:
        return {"error": str(e)}


url = input("🔗 Link ထည့်ပါ: ").strip()

if not url.startswith(("http://", "https://")):
    url = "https://" + url

print("\n" + "=" * 50)
print("🛡️ SCAM LINK CHECKER v11")
print("=" * 50)

parsed = urllib.parse.urlparse(url)
domain = parsed.hostname

if not domain:
    print("❌ URL မမှန်ပါ")
    raise SystemExit

print("\n🌐 Original URL:")
print(url)

print("\n🏠 Domain:")
print(domain)

# DNS / IP
try:
    ip = socket.gethostbyname(domain)
    print("\n📍 Server IP:")
    print(ip)

    # Server Information
    server = server_info(ip)

    if server and "error" not in server:
        print("\n🖥️ Server Information:")
        print(f"🌍 Country: {server.get('country') or 'Unknown'}")
        print(f"📍 Region: {server.get('region') or 'Unknown'}")
        print(f"🏙️ City: {server.get('city') or 'Unknown'}")
        print(f"🏢 ISP: {server.get('isp') or 'Unknown'}")
        print(f"🏛️ Organization: {server.get('org') or 'Unknown'}")
        print(f"🛰️ ASN: {server.get('asn') or 'Unknown'}")
    else:
        print("\n⚠️ Server information unavailable")

except Exception as e:
    print("\n📍 Server IP:")
    print("❌ မတွေ့ပါ")

# HTTPS
if parsed.scheme == "https":
    try:
        context = ssl.create_default_context()

        with socket.create_connection(
            (domain, 443), timeout=8
        ) as sock:
            with context.wrap_socket(
                sock, server_hostname=domain
            ) as ssock:

                cert = ssock.getpeercert()

                print("\n🔒 HTTPS:")
                print("✅ Valid connection")

                print("\n📜 Certificate:")

                subject = cert.get("subject", ())
                common_name = "Unknown"

                for item in subject:
                    for key, value in item:
                        if key == "commonName":
                            common_name = value

                print(f"Common Name: {common_name}")

                not_before = cert.get("notBefore")
                not_after = cert.get("notAfter")

                if not_before and not_after:
                    start_dt = datetime.strptime(
                        not_before, "%b %d %H:%M:%S %Y %Z"
                    ).replace(tzinfo=timezone.utc)

                    expiry_dt = datetime.strptime(
                        not_after, "%b %d %H:%M:%S %Y %Z"
                    ).replace(tzinfo=timezone.utc)

                    now = datetime.now(timezone.utc)
                    days_remaining = (expiry_dt - now).days

                    print(
                        f"📅 Valid From: "
                        f"{start_dt.strftime('%d %b %Y')}"
                    )
                    print(
                        f"📅 Expires: "
                        f"{expiry_dt.strftime('%d %b %Y')}"
                    )
                    print(
                        f"⏳ Days Remaining: "
                        f"{days_remaining} days"
                    )

                    if now > expiry_dt:
                        print("🔴 Certificate expired")
                    elif days_remaining <= 7:
                        print("🔴 Certificate expires within 7 days")
                    elif days_remaining <= 30:
                        print("🟠 Certificate expires within 30 days")
                    else:
                        print("🟢 Certificate currently valid")

    except Exception as e:
        print("\n🔒 HTTPS:")
        print("⚠️ SSL စစ်ဆေးမှု မအောင်မြင်ပါ")
else:
    print("\n🔒 HTTPS:")
    print("⚠️ HTTP only")

# Redirect / HTTP status
try:
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "Mozilla/5.0"}
    )

    opener = urllib.request.build_opener(
        urllib.request.HTTPRedirectHandler()
    )

    response = opener.open(request, timeout=10)

    final_url = response.geturl()
    status = response.status

    print("\n🔀 Final URL:")
    print(final_url)

    final_domain = urllib.parse.urlparse(
        final_url
    ).hostname

    if final_domain == domain:
        print("\n✅ Redirect domain unchanged")
    else:
        print("\n⚠️ Redirect domain changed")
        print("➡️", final_domain)

    print("\n📡 HTTP Status:")
    print(status)

except Exception as e:
    print("\n📡 HTTP Status:")
    print("❌ မရပါ")

# Suspicious URL keywords
suspicious_keywords = [
    "login",
    "verify",
    "verification",
    "password",
    "otp",
    "wallet",
    "bank",
    "payment",
    "bonus",
    "free",
    "claim",
    "gift",
    "prize",
    "crypto",
    "airdrop"
]

found = []

for word in suspicious_keywords:
    if word in url.lower():
        found.append(word)

print("\n🚨 Suspicious URL keywords:")

if found:
    print("⚠️ တွေ့ရှိသည်:", ", ".join(found))
else:
    print("✅ None found")

# Subdomain
parts = domain.split(".")

print("\n🧩 Domain structure:")

if len(parts) > 2:
    subdomain = ".".join(parts[:-2])
    print("⚠️ Subdomain detected")
    print("Subdomain:", subdomain)
else:
    print("✅ No unusual subdomain")

# WHOIS / Domain Age
print("\n🗓️ Domain Registration:")

try:
    whois_domain = ".".join(domain.split(".")[-2:])

    result = subprocess.run(
        ["whois", whois_domain],
        capture_output=True,
        text=True,
        timeout=15
    )

    whois_text = result.stdout + "\n" + result.stderr

    match = re.search(
        r"Creation\s+Date\s*:\s*(\d{4}-\d{2}-\d{2})",
        whois_text,
        re.IGNORECASE
    )

    if match:
        creation_date = match.group(1)

        creation = datetime.strptime(
            creation_date,
            "%Y-%m-%d"
        ).replace(tzinfo=timezone.utc)

        now = datetime.now(timezone.utc)
        days = (now - creation).days

        years = days // 365
        months = (days % 365) // 30

        print("📅 Creation Date:", creation_date)
        print(
            f"⏳ Domain Age: approximately "
            f"{years} years {months} months"
        )

        if days < 30:
            print("🚨 VERY NEW DOMAIN")
        elif days < 180:
            print("⚠️ Relatively new domain")
        else:
            print("✅ Domain is older than 6 months")

    else:
        print("⚠️ Creation Date မတွေ့ပါ")

except FileNotFoundError:
    print("⚠️ WHOIS command မရှိပါ")

except Exception as e:
    print("⚠️ WHOIS Error:", e)

# Reputation / Threat Indicators
reputation_flags = []

# Suspicious TLDs often seen in abuse reports
suspicious_tlds = [
    ".tk", ".ml", ".ga", ".cf", ".gq",
    ".top", ".xyz", ".click", ".work",
    ".buzz", ".cam"
]

if any(domain.lower().endswith(tld) for tld in suspicious_tlds):
    reputation_flags.append("Suspicious TLD pattern")

# Numeric-only subdomain
if len(parts) > 2 and parts[0].isdigit():
    reputation_flags.append("Numeric subdomain")

# Punycode / IDN indicator
if "xn--" in domain.lower():
    reputation_flags.append("Punycode/IDN domain")

# URL contains an IP address instead of a normal hostname
if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", domain):
    reputation_flags.append("IP address used as hostname")

print("\n🔎 Reputation Indicators:")

if reputation_flags:
    for flag in reputation_flags:
        print("⚠️", flag)
else:
    print("✅ No obvious reputation indicators")

# Redirect Chain
print("\n🔀 Redirect Chain:")

try:
    start_url = url if url.startswith(("http://", "https://")) else "https://" + url

    class RedirectTracker(urllib.request.HTTPRedirectHandler):
        def __init__(self):
            self.chain = []

        def redirect_request(self, req, fp, code, msg, headers, newurl):
            self.chain.append(newurl)
            return super().redirect_request(req, fp, code, msg, headers, newurl)

    tracker = RedirectTracker()

    opener = urllib.request.build_opener(tracker)

    response = opener.open(
        urllib.request.Request(
            start_url,
            headers={"User-Agent": "Mozilla/5.0"}
        ),
        timeout=10
    )

    print("1. " + start_url)

    for i, item in enumerate(tracker.chain, 2):
        print(f"{i}. {item}")

    print(f"🔢 Redirects followed: {len(tracker.chain)}")

except Exception:
    print("⚠️ Redirect chain could not be fully checked")

# Redirect Risk Analysis
redirect_count = len(tracker.chain)

if redirect_count > 0:
    print(f"⚠️ Redirects detected: {redirect_count}")

    original_host = urllib.parse.urlparse(start_url).hostname
    final_host = urllib.parse.urlparse(response.geturl()).hostname

    if original_host and final_host and original_host.lower() != final_host.lower():
        print("🚨 Final domain changed")
        redirect_domain_changed = True
    else:
        print("✅ Final domain unchanged")
        redirect_domain_changed = False
else:
    redirect_domain_changed = False

# VirusTotal Threat Intelligence
print("\n🛡️ VirusTotal Threat Intelligence:")

vt_result = virustotal_domain_check(domain)

if vt_result is None:
    print("⚠️ VT_API_KEY မတွေ့ပါ")
elif "error" in vt_result:
    print("⚠️ VirusTotal စစ်ဆေးမှု မအောင်မြင်ပါ")
    print(vt_result["error"])
else:
    print(f"🚨 Malicious: {vt_result['malicious']}")
    print(f"⚠️ Suspicious: {vt_result['suspicious']}")
    print(f"✅ Harmless: {vt_result['harmless']}")
    print(f"❓ Undetected: {vt_result['undetected']}")
    print(f"⭐ Reputation: {vt_result['reputation']}")

    print("\n🛡️ Detailed Threat Detection:")
    print(f"🦠 Malware: {vt_result.get('malware', 0)}")
    print(f"🎣 Phishing: {vt_result.get('phishing', 0)}")
    print(f"💻 Trojan: {vt_result.get('trojan', 0)}")
    print(f"🔐 Ransomware: {vt_result.get('ransomware', 0)}")

    detections = vt_result.get("detections", [])

    if detections:
        print("\n🚨 Detected by:")
        for item in detections[:10]:
            engine = item.get("engine", "Unknown")
            category = item.get("category", "Unknown")
            result_name = item.get("result") or "No label"
            print(f"• {engine}: {category} — {result_name}")
    else:
        print("\n✅ No individual malicious/suspicious detections reported")

# Risk Score
risk_score = 0
risk_reasons = []

# VirusTotal verdict priority
vt_verdict = "UNKNOWN"

if vt_result and "error" not in vt_result:
    vt_malicious = vt_result.get("malicious", 0)
    vt_suspicious = vt_result.get("suspicious", 0)

    if vt_malicious > 0:
        vt_verdict = "HIGH RISK"
    elif vt_suspicious > 0:
        vt_verdict = "SUSPICIOUS"
    else:
        vt_verdict = "NO MALICIOUS DETECTION"



# VirusTotal Risk
if vt_result and "error" not in vt_result:
    vt_malicious = vt_result.get("malicious", 0)
    vt_suspicious = vt_result.get("suspicious", 0)

    if vt_malicious > 0:
        risk_score += min(vt_malicious, 5)
        risk_reasons.append(
            f"VirusTotal Malicious detection: {vt_malicious}"
        )

    if vt_suspicious > 0:
        risk_score += min(vt_suspicious, 3)
        risk_reasons.append(
            f"VirusTotal Suspicious detection: {vt_suspicious}"
        )

for flag in reputation_flags:
    if flag not in ("Numeric subdomain", "IP address used as hostname"):
        risk_score += 1
        risk_reasons.append(flag)

if parsed.scheme != "https":
    risk_score += 2
    risk_reasons.append("HTTPS မသုံးထားပါ")

if found:
    risk_score += min(len(found), 3)
    risk_reasons.append("Suspicious URL keyword တွေ့ရှိသည်")

if len(parts) > 2:
    risk_score += 1
    risk_reasons.append("Subdomain ရှိသည်")

if redirect_domain_changed:
    risk_score += 2
    risk_reasons.append("Redirect domain ပြောင်းသွားသည်")

if "status" in locals() and status >= 400:
    risk_score += 2
    risk_reasons.append("HTTP error status")

if "days" in locals():
    if days < 30:
        risk_score += 3
        risk_reasons.append("Domain အလွန်အသစ်")
    elif days < 180:
        risk_score += 2
        risk_reasons.append("Domain အသစ်")

print("\n🛡️ VirusTotal Verdict:")
if vt_verdict == "HIGH RISK":
    print("🔴 HIGH RISK")
elif vt_verdict == "SUSPICIOUS":
    print("🟠 SUSPICIOUS")
elif vt_verdict == "NO MALICIOUS DETECTION":
    print("🟢 NO MALICIOUS DETECTION")
else:
    print("⚪ UNABLE TO VERIFY")

print("\n" + "=" * 50)
print("📊 RISK RESULT")
print("=" * 50)

print("🎯 Risk Score:", risk_score)

if risk_score <= 1:
    print("🟢 LOW RISK")
elif risk_score <= 3:
    print("🟡 SUSPICIOUS")
else:
    print("🔴 HIGH RISK")

if risk_reasons:
    print("\n🔎 Risk Factors:")
    for reason in risk_reasons:
        print("•", reason)
else:
    print("\n✅ No major risk factors detected.")

print("\n📌 NOTE")
print("Risk score is an automated technical estimate.")
print("It does NOT guarantee that a website is safe.")

print("\n📌 IMPORTANT")
print("HTTPS does NOT mean the website is trustworthy.")
print("IP address is the website server IP.")
print("It is NOT the Messenger sender's IP.")
print("Domain age alone does NOT prove a website is safe.")
print("Do not enter passwords, OTPs or payment details.")

print("=" * 50)
