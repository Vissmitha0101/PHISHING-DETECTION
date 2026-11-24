import re
from urllib.parse import urlparse

SUSPICIOUS_TLDS = {
    '.xyz', '.top', '.tk', '.buzz', '.click',
    '.link', '.work', '.gq', '.ml'
}

SHORTENERS = {
    'bit.ly', 'tinyurl.com', 't.co',
    'goo.gl', 'ow.ly', 'is.gd', 'buff.ly'
}

BRAND_KEYWORDS = {
    'paypal', 'apple', 'microsoft', 'google',
    'amazon', 'netflix', 'facebook', 'bank'
}


def analyze_url(url: str) -> dict:
    reasons = []
    score = 0

    if not url or len(url.strip()) < 4:
        return {
            'risk': 'High',
            'reasons': ['The link is too short or malformed'],
            'indicators': ['invalid_url']
        }

    raw = url.strip()

    if not re.match(r'^https?://', raw, re.I):
        parse_target = 'http://' + raw
    else:
        parse_target = raw

    try:
        p = urlparse(parse_target)
        host = (p.hostname or '').lower()
        path = (p.path or '').lower()
    except Exception:
        return {
            'risk': 'High',
            'reasons': ['Unable to parse this link'],
            'indicators': ['parse_error']
        }

    if not host:
        return {
            'risk': 'High',
            'reasons': ['The link does not contain a valid hostname'],
            'indicators': ['invalid_host']
        }

    full = host + path

    # IP address in URL
    if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', host):
        score = max(score, 85)
        reasons.append("The link uses an IP address instead of a normal domain")

    # @ symbol in URL
    if '@' in p.netloc:
        score = max(score, 90)
        reasons.append("The link contains an unusual @ symbol")

    # URL shorteners
    if host in SHORTENERS:
        score = max(score, 55)
        reasons.append("The link uses a URL shortening service")

    # Suspicious domain extension
    if any(host.endswith(tld) for tld in SUSPICIOUS_TLDS):
        score = max(score, 60)
        reasons.append("The domain uses a commonly abused extension")

    # Possible brand impersonation
    for brand in BRAND_KEYWORDS:
        if brand in host:
            trusted_domains = (
                brand + '.com',
                brand + '.in',
                brand + '.org',
                brand + '.net'
            )

            if not any(host == domain or host.endswith('.' + domain)
                       for domain in trusted_domains):
                score = max(score, 75)
                reasons.append(
                    "The domain may be impersonating a trusted brand"
                )
                break

    # Too many hyphens or numbers
    if host.count('-') >= 3 or len(re.findall(r'\d', host)) >= 5:
        score = max(score, 50)
        reasons.append("The domain contains an unusual number of hyphens or digits")

    # Suspicious words in URL path
    suspicious_words = [
        'login', 'verify', 'update', 'secure',
        'account', 'password', 'banking'
    ]

    if any(word in full for word in suspicious_words):
        if not reasons:
            score = max(score, 35)
            reasons.append("The URL contains words commonly used in phishing links")

    # Very long URL
    if len(raw) > 150:
        score = max(score, 40)
        reasons.append("The URL is unusually long")

    # Risk calculation
    if not reasons:
        risk = 'Low'
        reasons.append(
            "No obvious suspicious features were found. "
            "This does not guarantee the link is safe."
        )
    elif score >= 70:
        risk = 'High'
    else:
        risk = 'Medium'

    return {
        'risk': risk,
        'reasons': reasons,
        'indicators': reasons[:]
    }


def analyze_email(email: str) -> dict:
    reasons = []
    score = 0

    if not email or not email.strip():
        return {
            'risk': 'High',
            'reasons': ['Email content is empty'],
            'indicators': ['empty_email'],
            'links': []
        }

    email_lower = email.lower()

    # Urgent language
    urgency_patterns = [
        r'urgent',
        r'immediately',
        r'account.*suspend',
        r'act now',
        r'within 24 hours',
        r'limited time'
    ]

    if any(re.search(pattern, email_lower) for pattern in urgency_patterns):
        score += 30
        reasons.append("The email uses urgent or threatening language")

    # Generic greeting
    if re.search(r'hello user|dear customer|dear user|dear valued', email_lower):
        score += 15
        reasons.append("The email uses a generic greeting")

    # Sensitive information requests
    sensitive_patterns = [
        'password', 'otp', 'bank details',
        'credit card', 'social security',
        'verify your account', 'personal information'
    ]

    if any(word in email_lower for word in sensitive_patterns):
        score += 35
        reasons.append("The email mentions sensitive information or account verification")

    # Sender and reply-to mismatch
    from_match = re.search(r'from:\s*.*?<([^>]+)>', email_lower)
    reply_match = re.search(r'reply-to:\s*.*?<([^>]+)>', email_lower)

    if from_match and reply_match:
        if from_match.group(1) != reply_match.group(1):
            score += 40
            reasons.append("The sender and reply-to addresses do not match")

    # Email authentication failures
    auth_failures = [
        'spf=fail', 'dkim=fail', 'dmarc=fail'
    ]

    if any(item in email_lower for item in auth_failures):
        score += 50
        reasons.append("Email authentication checks show a failure")

    # Extract links
    urls = re.findall(r'https?://[^\s<>"]+', email, re.I)
    links = []

    for url in urls[:5]:
        url = url.rstrip('.,);]')
        result = analyze_url(url)

        links.append({
            'url': url,
            'risk': result['risk']
        })

        if result['risk'] == 'High':
            score += 25
            reasons.append("The email contains a high-risk link")
        elif result['risk'] == 'Medium':
            score += 15
            reasons.append("The email contains a suspicious link")

    # Final risk calculation
    if not reasons:
        risk = 'Low'
        reasons.append(
            "No obvious phishing indicators were found. "
            "This does not guarantee the email is safe."
        )
    elif score >= 60:
        risk = 'High'
    else:
        risk = 'Medium'

    return {
        'risk': risk,
        'reasons': reasons,
        'indicators': reasons[:],
        'links': links
    }
