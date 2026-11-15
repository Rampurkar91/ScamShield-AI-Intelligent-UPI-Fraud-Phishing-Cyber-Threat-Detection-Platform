"""Opt-in provider lookups. These query fixed provider hosts, never the submitted URL."""
import base64
from urllib.parse import urlsplit, parse_qsl
import ipaddress
import re
import httpx
from .config import settings
from .scanners import score_indicators


def eligible_url(value):
    value = value.strip()
    if '://' not in value:
        value = 'https://' + value
    try:
        parsed = urlsplit(value)
        host = parsed.hostname
        if parsed.scheme not in ('http', 'https') or not host or parsed.username or parsed.password or len(value) > 2048 or any(c.isspace() for c in value):
            return None
        # Do not send obvious private/local URLs or credential-bearing query strings.
        if '.' not in host or host.lower().endswith(('.local', '.localhost', '.internal')):
            return None
        try:
            if not ipaddress.ip_address(host).is_global:
                return None
        except ValueError:
            pass
        if any(re.search(r'password|token|secret|otp|credential|key|auth', k, re.I) for k, _ in parse_qsl(parsed.query, keep_blank_values=True)):
            return None
        return value
    except ValueError:
        return None


def enrich_url(result, raw_url, consent):
    providers = {'google_safe_browsing': 'not_configured' if not settings.google_safe_browsing_api_key else 'skipped',
                 'virustotal': 'not_configured' if not settings.virustotal_api_key else 'skipped'}
    value = eligible_url(raw_url)
    indicators = list(result['indicators'])
    limitations = list(result['limitations'])
    if consent and not value:
        limitations.append('External lookups skipped: URL is invalid, local, or may contain credentials.')
    if consent and value:
        if settings.google_safe_browsing_api_key:
            try:
                response = httpx.post('https://safebrowsing.googleapis.com/v4/threatMatches:find', params={'key': settings.google_safe_browsing_api_key}, json={'client': {'clientId': 'scamshield', 'clientVersion': '1.0'}, 'threatInfo': {'threatTypes': ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'], 'platformTypes': ['ANY_PLATFORM'], 'threatEntryTypes': ['URL'], 'threatEntries': [{'url': value}]}}, timeout=4.0)
                response.raise_for_status()
                data = response.json()
                if not isinstance(data, dict) or not isinstance(data.get('matches', []), list):
                    raise ValueError('Invalid provider response')
                providers['google_safe_browsing'] = 'match' if data.get('matches') else 'no_match'
                if data.get('matches'):
                    indicators.append({'name': 'Google Safe Browsing match', 'severity': 'high', 'explanation': 'Google returned a threat-list match for the submitted URL.'})
            except (httpx.HTTPError, ValueError, TypeError):
                providers['google_safe_browsing'] = 'unavailable'
        if settings.virustotal_api_key:
            try:
                identifier = base64.urlsafe_b64encode(value.encode()).decode().rstrip('=')
                response = httpx.get('https://www.virustotal.com/api/v3/urls/' + identifier, headers={'x-apikey': settings.virustotal_api_key}, timeout=4.0)
                if response.status_code == 404:
                    providers['virustotal'] = 'not_found'
                else:
                    response.raise_for_status()
                    stats = response.json()['data']['attributes']['last_analysis_stats']
                    malicious, suspicious = stats['malicious'], stats['suspicious']
                    if not isinstance(malicious, int) or not isinstance(suspicious, int) or malicious < 0 or suspicious < 0:
                        raise ValueError('Invalid provider response')
                    providers['virustotal'] = 'match' if malicious or suspicious else 'no_match'
                    if malicious or suspicious:
                        indicators.append({'name': 'VirusTotal detections', 'severity': 'high', 'explanation': f'Existing VirusTotal report: {malicious} malicious and {suspicious} suspicious detections.'})
            except (httpx.HTTPError, ValueError, TypeError, KeyError):
                providers['virustotal'] = 'unavailable'
    limitations = [x for x in limitations if x != 'Live TLS certificate and threat intelligence checks were not performed.']
    limitations.append('Live TLS certificate validation was not performed; a provider no-match does not establish safety.')
    if not consent:
        limitations.append('External lookups were not requested; URL was analyzed locally.')
    result = score_indicators(indicators, limitations)
    result['providers'] = providers
    result['threat_intelligence'] = 'checked' if any(s in ('match', 'no_match') for s in providers.values()) else 'not_verified'
    return result
