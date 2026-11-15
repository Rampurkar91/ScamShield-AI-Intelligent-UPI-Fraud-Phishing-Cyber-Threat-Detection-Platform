"""Local heuristic checks. Scores are indicators, not proof of fraud."""
import ipaddress
import re
from difflib import SequenceMatcher
from urllib.parse import urlsplit, parse_qsl

BRANDS = ('google', 'amazon', 'paytm', 'phonepe', 'sbi', 'hdfcbank', 'microsoft')
SHORTENERS = {'bit.ly', 'tinyurl.com', 't.co', 'cutt.ly', 'is.gd'}

def score_indicators(indicators, limitations, *, unknown=False):
    score = None if unknown else min(100, sum({'low': 10, 'medium': 25, 'high': 40}[i['severity']] for i in indicators))
    return {'score': score, 'category': 'unknown' if score is None else 'high' if score >= 60 else 'medium' if score >= 25 else 'low', 'indicators': indicators, 'explanation': 'Insufficient content to assess risk.' if unknown else 'Score is the capped sum of heuristic indicator weights; a low score does not establish safety.', 'recommended_actions': ['Verify requests through an official channel.', 'Never share OTPs or your UPI PIN.', 'Do not pay to receive money.'], 'threat_intelligence': 'not_configured', 'status': 'partial', 'limitations': list(dict.fromkeys(limitations))}

def analyze(kind, text):
    indicators = []
    limitations = []
    def add(name, severity, explanation):
        indicators.append({'name': name, 'severity': severity, 'explanation': explanation})
    def url_checks(value):
        try:
            u = urlsplit(value if '://' in value else 'https://' + value)
            host = (u.hostname or '').lower().rstrip('.')
            if not host or u.scheme not in ('http', 'https'):
                raise ValueError()
            if u.scheme != 'https': add('Unencrypted URL', 'medium', 'HTTP does not encrypt traffic.')
            try:
                ipaddress.ip_address(host)
                add('IP address host', 'high', 'The URL uses an IP address rather than a domain.')
            except ValueError: pass
            if host in SHORTENERS: add('URL shortener', 'medium', 'The destination is hidden behind a short link.')
            if host.count('.') >= 3: add('Many subdomains', 'low', 'Extra subdomains can disguise the registered domain.')
            if '@' in u.netloc or 'xn--' in host: add('Obfuscated host', 'high', 'User information or an internationalized domain may obscure the destination.')
            if len(value) > 150: add('Long URL', 'low', 'Long addresses can conceal suspicious components.')
            labels = host.split('.')
            for label in labels:
                if any(label != b and len(label) >= 4 and SequenceMatcher(None, label, b).ratio() >= .8 for b in BRANDS):
                    add('Possible brand imitation', 'medium', 'A domain label resembles a known brand; verify independently.')
                    break
            if any(re.search(r'password|token|otp|credential', k, re.I) for k, _ in parse_qsl(u.query)):
                add('Sensitive query parameter', 'high', 'The URL contains a parameter associated with credentials.')
        except ValueError:
            add('Invalid URL', 'medium', 'The address could not be parsed as an HTTP URL.')
        limitations.append('Live TLS certificate and threat intelligence checks were not performed.')
    def message_checks(value):
        rules = [
            (r'\b(urgent|immediately|act now|within 24 hours|account (?:blocked|suspended))\b|तुरंत|तत्काल', 'Urgency or pressure', 'medium'),
            (r'\b(otp|one.time.password|upi\s*pin|cvv)\b|ओटीपी|पिन', 'Sensitive credential request', 'high'),
            (r'\b(refund|cashback|prize|lottery|reward)\b|इनाम|रिफंड', 'Financial lure', 'medium'),
            (r'\b(collect request|request money|approve.{0,30}(?:receive|refund)|pay.{0,30}receive)\b', 'Possible collect-request scam', 'high'),
            (r'\b(payment (?:successful|received|confirmed)|transaction successful)\b', 'Payment confirmation claim', 'low'),
            (r'\b(verify|update|confirm).{0,35}\b(account|kyc|bank|password)\b', 'Account verification pressure', 'medium'),
            (r'\b(screen sharing|remote access|anydesk|teamviewer)\b', 'Remote access request', 'high'),
        ]
        for pattern, name, severity in rules:
            if re.search(pattern, value, re.I): add(name, severity, 'Matched a potentially risky phrase; context matters.')
        for link in re.findall(r'https?://[^\s<>"\']+', value, re.I)[:5]: url_checks(link.rstrip('.,)'))
        limitations.append('AI classification was not performed; local rules only.')
    if kind == 'url': url_checks(text.strip())
    elif kind in ('message', 'upi'): message_checks(text)
    elif kind == 'email':
        message_checks(text)
        if re.search(r'(?im)^reply-to:\s*(.+)$', text) and re.search(r'(?im)^from:\s*(.+)$', text):
            from email.utils import parseaddr
            f = re.search(r'(?im)^from:\s*(.+)$', text).group(1)
            r = re.search(r'(?im)^reply-to:\s*(.+)$', text).group(1)
            fd = parseaddr(f)[1].partition('@')[2].lower(); rd = parseaddr(r)[1].partition('@')[2].lower()
            if fd and rd and fd != rd: add('Reply-to domain mismatch', 'high', 'From and Reply-To domains differ.')
        limitations.append('Email authentication headers were not independently verified.')
    elif kind == 'code':
        rules = [(r'(?i)(?:api[_-]?key|secret|password)\s*[:=]\s*[\'"][^\'"]{8,}[\'"]', 'Possible hardcoded secret', 'high'), (r'(?i)\bverify\s*=\s*False\b', 'TLS verification disabled', 'high'), (r'(?i)\b(?:eval|exec)\s*\(', 'Dynamic code execution', 'medium'), (r'(?i)\bdebug\s*=\s*True\b', 'Debug mode enabled', 'medium')]
        for pattern, name, severity in rules:
            if re.search(pattern, text): add(name, severity, 'A potentially unsafe pattern was detected; review manually.')
        limitations.append('Dependency vulnerability and repository-wide scans were not performed.')
    else: raise ValueError('Unsupported scan type')
    return score_indicators(indicators, limitations)
