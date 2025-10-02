from urllib.parse import urlparse
import ipaddress

SUSPICIOUS_TLDS = {'tk','cf','ga','gq','ml'}

def analyze_url(url: str):
    issues = []
    try:
        parsed = urlparse(url if url.startswith(('http://','https://')) else 'http://' + url)
    except Exception as e:
        return {'valid': False, 'issues': [f'Parse error: {e}']}

    host = parsed.hostname or ''
    path = parsed.path or ''
    netloc = parsed.netloc or host

    try:
        if host:
            ipaddress.ip_address(host)
            issues.append('Hostname is an IP address (suspicious)')
    except Exception:
        pass

    if '@' in url:
        issues.append("Contains '@' (possible credential phishing)")

    if len(url) > 75:
        issues.append('URL is long (common in phishing links)')

    if host.count('-') >= 3:
        issues.append('Many hyphens in hostname (typosquatting technique)')

    if host.count('.') >= 4:
        issues.append('Many subdomain levels')

    tld = host.split('.')[-1].lower() if '.' in host else ''
    if tld in SUSPICIOUS_TLDS:
        issues.append(f'TLD {tld} is commonly abused for phishing')

    if 'xn--' in host:
        issues.append('Punycode (xn--) detected — possible homograph attack')

    if ':' in netloc and not netloc.endswith(':80') and not netloc.endswith(':443'):
        issues.append('Nonstandard port used')

    verdict = 'suspicious' if issues else 'likely OK'
    return {'valid': True, 'host': host, 'path': path, 'issues': issues, 'verdict': verdict}
