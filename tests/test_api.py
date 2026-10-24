from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_health_endpoint():
    response = client.get('/health')
    assert response.status_code == 200
    assert response.json()['status'] == 'ok'


def test_analyze_endpoint_returns_findings():
    response = client.post('/api/analyze', json={'code': 'eval(user_input)\n'})
    assert response.status_code == 200
    assert response.json()['findings'][0]['rule_id'] == 'CS001'


def test_empty_source_rejected():
    response = client.post('/api/analyze', json={'code': '  '})
    assert response.status_code == 422


def test_rules_endpoint():
    response = client.get('/api/rules')
    assert response.status_code == 200
    assert response.json()['count'] == 11


def test_homepage_loads():
    response = client.get('/')
    assert response.status_code == 200
    assert 'CodeSentinel' in response.text
    assert 'Developed by' in response.text
    assert '/docs' not in response.text


def test_api_documentation_is_disabled():
    for path in ('/docs', '/redoc', '/openapi.json'):
        response = client.get(path)
        assert response.status_code == 404
