import socket
import ssl
import urllib.request
import urllib.parse
import re
import subprocess
from datetime import datetime, timezone

url = input("🔗 Link ထည့်ပါ: ").strip()

if not url.startswith(("http://", "https://")):
    url = "https://" + url

print("\n" + "=" * 50)
print("🛡️ SCAM LINK CHECKER v5")
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
                print(cert.get("subject"))

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

# Final result
print("\n" + "=" * 50)
print("📊 RESULT")
print("=" * 50)

if found:
    print("⚠️ Suspicious URL keywords တွေ့ရှိပါတယ်။")
else:
    print("ℹ️ No obvious suspicious keywords detected.")

print("\n📌 IMPORTANT")
print("HTTPS does NOT mean the website is trustworthy.")
print("IP address is the website server IP.")
print("It is NOT the Messenger sender's IP.")
print("Domain age alone does NOT prove a website is safe.")
print("Do not enter passwords, OTPs or payment details.")

print("=" * 50)
