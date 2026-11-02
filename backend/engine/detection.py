
import ipaddress
import re
from urllib.parse import urlsplit, unquote


URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "ow.ly",
    "rb.gy", "cutt.ly", "shorturl.at", "rebrand.ly"
}

HIGH_RISK_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".ps1", ".vbs",
    ".js", ".hta", ".msi", ".iso", ".img", ".lnk"
}

BRAND_DOMAINS = {
    "paypal": ["paypal.com"],
    "microsoft": ["microsoft.com", "live.com", "office.com"],
    "google": ["google.com"],
    "apple": ["apple.com"],
    "amazon": ["amazon.com"],
    "facebook": ["facebook.com", "fb.com"],
    "instagram": ["instagram.com"],
    "netflix": ["netflix.com"],
    "outlook": ["outlook.com", "office.com"]
}

SUSPICIOUS_URL_TERMS = {
    "login", "verify", "password", "account", "wallet",
    "reset", "secure", "update", "bank", "signin",
    "auth", "credential", "payment", "confirm", "recover"
}


def _domain_matches(hostname, domain):
    """True only for the domain itself or a genuine subdomain."""
    return hostname == domain or hostname.endswith("." + domain)


def analyze_url(url):
    """
    Explainable URL risk analysis.
    This is a heuristic detector, not a definitive reputation verdict.
    """

    result = {
        "url": str(url),
        "hostname": "",
        "risk_indicators": [],
        "indicator_count": 0,
        "risk_score": 0,
        "risk_level": "UNKNOWN",
        "verdict": "UNKNOWN",
        "detection_method": "HEURISTIC",
        "limitations": [
            "No heuristic can prove a URL is safe or malicious.",
            "Live reputation and redirect checks are not performed here."
        ]
    }

    if not isinstance(url, str) or not url.strip():
        result["risk_indicators"] = ["Empty or invalid URL input"]
        result["indicator_count"] = 1
        result["risk_score"] = 20
        result["risk_level"] = "MEDIUM"
        result["verdict"] = "SUSPICIOUS"
        return result

    original_url = url.strip()

    # Parse first, then validate. Never visit or download the URL here.
    candidate = original_url
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", candidate):
        candidate = "https://" + candidate

    try:
        parsed = urlsplit(candidate)
        hostname = (parsed.hostname or "").lower().rstrip(".")
        port = parsed.port  # May raise ValueError for malformed ports.
    except ValueError:
        result["risk_indicators"] = ["Malformed URL or invalid port"]
        result["indicator_count"] = 1
        result["risk_score"] = 35
        result["risk_level"] = "HIGH"
        result["verdict"] = "SUSPICIOUS"
        return result

    result["hostname"] = hostname

    score = 0
    indicators = []

    def flag(points, reason):
        nonlocal score
        score += points
        indicators.append(reason)

    if parsed.scheme.lower() not in {"http", "https"}:
        flag(25, "Uses an unexpected URL scheme")

    if not hostname or "." not in hostname:
        flag(20, "Hostname is missing or unusual")

    if parsed.username is not None or parsed.password is not None:
        flag(25, "Contains user information before the hostname")

    try:
        ipaddress.ip_address(hostname)
        flag(25, "Uses an IP address instead of a domain name")
    except ValueError:
        pass

    if hostname in URL_SHORTENERS:
        flag(15, "Uses a known URL-shortening service")

    if any(label.startswith("xn--") for label in hostname.split(".")):
        flag(20, "Contains a Punycode domain label")

    if len(candidate) > 180:
        flag(10, "URL is unusually long")
    elif len(candidate) > 100:
        flag(5, "URL is longer than typical")

    if len(hostname.split(".")) >= 5:
        flag(10, "Contains an unusually deep subdomain structure")

    if port is not None and port not in {80, 443}:
        flag(10, "Uses a non-standard web port")

    decoded_url = unquote(candidate).lower()
    matched_terms = sorted(
        term for term in SUSPICIOUS_URL_TERMS
        if re.search(r"(?<![a-z])" + re.escape(term) + r"(?![a-z])",
                     decoded_url)
    )
    if matched_terms:
        # Keywords are weak evidence; do not treat them as proof.
        flag(5, "Contains sensitive terms: " + ", ".join(matched_terms))

    path_lower = parsed.path.lower()
    if any(path_lower.endswith(ext) for ext in HIGH_RISK_EXTENSIONS):
        flag(20, "URL path ends in a potentially risky executable or script extension")

    # Detect brand names used in a hostname that is not the real brand domain.
    # Example: paypal.com.attacker.example is not paypal.com.
    brand_impersonation = []
    for brand, legitimate_domains in BRAND_DOMAINS.items():
        if brand in hostname:
            if not any(
                _domain_matches(hostname, domain)
                for domain in legitimate_domains
            ):
                brand_impersonation.append(brand)

    if brand_impersonation:
        flag(
            25,
            "Possible brand impersonation in hostname: "
            + ", ".join(sorted(brand_impersonation))
        )

    score = min(score, 100)

    if score >= 60:
        risk_level = "HIGH"
    elif score >= 30:
        risk_level = "MEDIUM"
    elif score > 0:
        risk_level = "LOW"
    else:
        risk_level = "LOW"

    # Keep the existing verdict names so the combined risk engine can use them.
    verdict = "SUSPICIOUS" if score >= 20 else "NO OBVIOUS INDICATORS"

    result.update({
        "risk_indicators": indicators,
        "indicator_count": len(indicators),
        "risk_score": score,
        "risk_level": risk_level,
        "verdict": verdict,
        "matched_sensitive_terms": matched_terms,
        "possible_brand_impersonation": brand_impersonation
    })

    return result



from email import policy
from email.parser import Parser
from email.utils import parseaddr
import re


BRAND_EMAIL_DOMAINS = {
    "paypal": {"paypal.com"},
    "microsoft": {"microsoft.com", "outlook.com", "live.com", "office.com"},
    "google": {"google.com", "gmail.com"},
    "apple": {"apple.com", "icloud.com"},
    "amazon": {"amazon.com"},
    "netflix": {"netflix.com"},
    "facebook": {"facebook.com", "fb.com"},
}

PHISHING_PHRASES = {
    "verify your account": 10,
    "account suspended": 15,
    "password expires": 10,
    "confirm your password": 15,
    "unusual activity": 8,
    "payment failed": 8,
    "urgent action required": 12,
    "click here immediately": 10,
    "wire transfer": 8,
    "gift card": 8,
    "update your payment": 10,
    "your account will be closed": 12,
}


def _email_domain(address):
    """Extract and normalize a domain from an email address."""
    _, address = parseaddr(str(address or ""))
    if "@" not in address:
        return ""
    return address.rsplit("@", 1)[1].strip().lower().rstrip(".")


def _domain_is_exact_or_subdomain(host, domain):
    return host == domain or host.endswith("." + domain)


def analyze_email_phishing(raw_email):
    """
    Score email-level phishing indicators.

    This function does not execute attachments, visit links,
    or treat missing authentication headers as a failure.
    """

    message = Parser(policy=policy.default).parsestr(raw_email or "")

    sender_name, sender_address = parseaddr(
        str(message.get("From", ""))
    )
    reply_name, reply_address = parseaddr(
        str(message.get("Reply-To", ""))
    )

    sender_domain = _email_domain(sender_address)
    reply_domain = _email_domain(reply_address)

    subject = str(message.get("Subject", ""))
    body_parts = []

    for part in message.walk():
        if part.get_content_maintype() == "multipart":
            continue
        if part.get_content_disposition() == "attachment":
            continue
        if part.get_content_type() not in {"text/plain", "text/html"}:
            continue

        try:
            content = part.get_content()
            if isinstance(content, str):
                body_parts.append(content)
        except (KeyError, TypeError, UnicodeError):
            continue

    body = "\n".join(body_parts)
    combined_text = f"{subject}\n{body}".lower()

    score = 0
    findings = []

    def add_finding(points, category, detail):
        nonlocal score
        score += points
        findings.append({
            "category": category,
            "points": points,
            "detail": detail
        })

    # 1. Sender and reply-to mismatch
    if sender_domain and reply_domain and sender_domain != reply_domain:
        add_finding(
            15,
            "sender_mismatch",
            f"From domain ({sender_domain}) differs from "
            f"Reply-To domain ({reply_domain})."
        )

    # 2. Authentication results, if a trusted mail system supplied them
    auth_headers = message.get_all("Authentication-Results", [])
    auth_text = " ".join(str(value) for value in auth_headers).lower()

    auth_status = {}

    for mechanism in ("spf", "dkim", "dmarc"):
        matches = re.findall(
            rf"\b{mechanism}\s*=\s*(pass|fail|softfail|neutral|none|temperror|permerror)\b",
            auth_text
        )
        if matches:
            auth_status[mechanism] = matches

            if "fail" in matches:
                add_finding(
                    15,
                    "email_authentication",
                    f"{mechanism.upper()} authentication reported fail."
                )
            elif "softfail" in matches:
                add_finding(
                    7,
                    "email_authentication",
                    f"{mechanism.upper()} authentication reported softfail."
                )

    # Missing authentication results are unknown, not a failure.
    if not auth_headers:
        auth_note = "Authentication-Results header not provided."
    else:
        auth_note = "Authentication results were present; inspect the sending mail system."

    # 3. Brand name in the display name with an unrelated sender domain
    display_name = sender_name.lower()

    for brand, legitimate_domains in BRAND_EMAIL_DOMAINS.items():
        if brand in display_name:
            if sender_domain and not any(
                _domain_is_exact_or_subdomain(sender_domain, domain)
                for domain in legitimate_domains
            ):
                add_finding(
                    20,
                    "possible_brand_impersonation",
                    f"Display name references {brand}, but sender domain "
                    f"is {sender_domain}."
                )
                break

    # 4. Social-engineering phrases
    matched_phrases = []

    for phrase, points in PHISHING_PHRASES.items():
        if phrase in combined_text:
            matched_phrases.append(phrase)

    if matched_phrases:
        # Cap wording evidence to avoid over-weighting a long email.
        language_points = min(
            25,
            sum(PHISHING_PHRASES[phrase] for phrase in matched_phrases)
        )
        add_finding(
            language_points,
            "social_engineering_language",
            "Potentially manipulative wording: "
            + ", ".join(sorted(matched_phrases))
        )

    # 5. URL evidence from the existing analyzer
    extracted_urls = []

    for part in message.walk():
        if part.get_content_type() == "text/html":
            try:
                from html.parser import HTMLParser

                class _LinkExtractor(HTMLParser):
                    def __init__(self):
                        super().__init__()
                        self.links = []

                    def handle_starttag(self, tag, attrs):
                        if tag.lower() == "a":
                            for key, value in attrs:
                                if key.lower() == "href" and value:
                                    self.links.append(value)

                parser = _LinkExtractor()
                parser.feed(part.get_content())
                extracted_urls.extend(parser.links)
            except (KeyError, TypeError, UnicodeError):
                pass

    # Extract plain-text URLs as well.
    extracted_urls.extend(
        re.findall(r"""https?://[^\s<>"']+""", body, flags=re.IGNORECASE)
    )
    extracted_urls = list(dict.fromkeys(extracted_urls))

    url_results = [analyze_url(url) for url in extracted_urls]

    high_risk_urls = [
        item for item in url_results
        if item.get("risk_score", 0) >= 30
        or item.get("verdict") == "MALICIOUS"
    ]

    if high_risk_urls:
        add_finding(
            min(30, 15 * len(high_risk_urls)),
            "suspicious_urls",
            f"{len(high_risk_urls)} URL(s) have elevated heuristic risk."
        )

    score = min(score, 100)

    if score >= 60:
        risk_level = "HIGH"
    elif score >= 30:
        risk_level = "MEDIUM"
    elif score >= 10:
        risk_level = "LOW"
    else:
        risk_level = "MINIMAL"

    return {
        "sender_name": sender_name,
        "sender_address": sender_address,
        "sender_domain": sender_domain,
        "reply_to": reply_address,
        "reply_to_domain": reply_domain,
        "subject": subject,
        "authentication_status": auth_status,
        "authentication_note": auth_note,
        "matched_phishing_phrases": matched_phrases,
        "extracted_urls": extracted_urls,
        "url_analysis": url_results,
        "risk_score": score,
        "risk_level": risk_level,
        "verdict": (
            "SUSPICIOUS" if score >= 30
            else "REVIEW" if score >= 10
            else "NO STRONG INDICATORS"
        ),
        "findings": findings,
        "limitations": [
            "This is a heuristic score, not a calibrated probability.",
            "Authentication headers can be forged outside a trusted mail path.",
            "Missing authentication results are not treated as authentication failure.",
            "Low risk does not prove the email is legitimate."
        ]
    }
