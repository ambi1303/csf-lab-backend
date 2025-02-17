import requests

BASE_URL = "http://localhost:8000"

# Test scan start
response = requests.post(f"{BASE_URL}/scan/start", json={"target_url": "http://example.com"})
print(response.json())

# Test fetch vulnerabilities
response = requests.post(f"{BASE_URL}/fetch_nvd")
print(response.json())

# Test get vulnerabilities
response = requests.get(f"{BASE_URL}/vulnerabilities")
print(response.json())
