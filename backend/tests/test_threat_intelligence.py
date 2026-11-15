import httpx
from app import threat_intelligence as ti
from app.scanners import analyze


def response(status, json):
    return httpx.Response(status, json=json, request=httpx.Request('GET', 'https://provider.test'))


def test_disabled_and_privacy(monkeypatch):
    monkeypatch.setattr(ti.settings, 'google_safe_browsing_api_key', '')
    monkeypatch.setattr(ti.settings, 'virustotal_api_key', '')
    r = ti.enrich_url(analyze('url', 'https://example.com'), 'https://example.com', True)
    assert set(r['providers'].values()) == {'not_configured'}
    monkeypatch.setattr(ti.settings, 'google_safe_browsing_api_key', 'test')
    monkeypatch.setattr(ti.httpx, 'post', lambda *a, **kw: (_ for _ in ()).throw(AssertionError('must not call')))
    for value in ('https://example.com/?token=secret', 'http://127.0.0.1', 'https://u:p@example.com', 'http://host.internal'):
        r = ti.enrich_url(analyze('url', value), value, True)
        assert r['providers']['google_safe_browsing'] == 'skipped'
    r = ti.enrich_url(analyze('url', 'https://example.com'), 'https://example.com', False)
    assert r['providers']['google_safe_browsing'] == 'skipped'


def test_match_no_match_and_no_url_fetch(monkeypatch):
    monkeypatch.setattr(ti.settings, 'google_safe_browsing_api_key', 'test')
    monkeypatch.setattr(ti.settings, 'virustotal_api_key', 'test')
    def post(url, **kwargs):
        assert url == 'https://safebrowsing.googleapis.com/v4/threatMatches:find'
        return response(200, {'matches': [{'threatType': 'SOCIAL_ENGINEERING'}]})
    def get(url, **kwargs):
        assert url.startswith('https://www.virustotal.com/api/v3/urls/')
        return response(200, {'data': {'attributes': {'last_analysis_stats': {'malicious': 0, 'suspicious': 0}}}})
    monkeypatch.setattr(ti.httpx, 'post', post); monkeypatch.setattr(ti.httpx, 'get', get)
    r = ti.enrich_url(analyze('url', 'https://example.com'), 'https://example.com', True)
    assert r['providers'] == {'google_safe_browsing': 'match', 'virustotal': 'no_match'}
    assert r['score'] >= 40 and r['threat_intelligence'] == 'checked'


def test_failures_and_unknown(monkeypatch):
    monkeypatch.setattr(ti.settings, 'google_safe_browsing_api_key', 'test')
    monkeypatch.setattr(ti.settings, 'virustotal_api_key', 'test')
    def fail(*args, **kwargs): raise httpx.ConnectTimeout('timed out')
    monkeypatch.setattr(ti.httpx, 'post', fail)
    monkeypatch.setattr(ti.httpx, 'get', lambda *a, **k: response(404, {}))
    r = ti.enrich_url(analyze('url', 'https://example.com'), 'https://example.com', True)
    assert r['providers'] == {'google_safe_browsing': 'unavailable', 'virustotal': 'not_found'}
    assert r['threat_intelligence'] == 'not_verified' and r['status'] == 'partial'
    monkeypatch.setattr(ti.httpx, 'post', lambda *a, **k: response(200, {'matches': 'invalid'}))
    r = ti.enrich_url(analyze('url', 'https://example.com'), 'https://example.com', True)
    assert r['providers']['google_safe_browsing'] == 'unavailable'


def test_production_origin_validation():
    import pytest
    from app.config import Settings
    base = dict(database_url='postgresql://localhost/db', jwt_secret_key='x' * 40, environment='production')
    Settings(**base, frontend_url='https://example.com,https://preview.example.com').validate_security()
    for origin in ('https://example.com,http://evil.example', 'https://example.com/path', '*', 'https://example.com?bad=1'):
        with pytest.raises(ValueError):
            Settings(**base, frontend_url=origin).validate_security()
