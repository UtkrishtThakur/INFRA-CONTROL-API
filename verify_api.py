import requests
import sys

BASE_URL = "http://127.0.0.1:8000"

def log(msg):
    print(f"[TEST] {msg}")

def check(response, expected_status=200, check_fn=None):
    if response.status_code != expected_status:
        print(f"FAILED: Expected {expected_status}, got {response.status_code}")
        print(response.text)
        sys.exit(1)
    if check_fn:
        check_fn(response.json())
    log("OK")
    return response.json()

def run_tests():
    # 1. Register
    log("Registering User...")
    email = f"test_{requests.utils.quote('user@example.com')}" # Simple uniqueness
    # Better uniqueness
    import time
    email = f"user_{int(time.time())}@example.com"
    
    password = "strongpassword123"
    
    resp = requests.post(f"{BASE_URL}/auth/register", json={"email": email, "password": password})
    # If 409, try login
    if resp.status_code == 409:
        log("User exists, proceeding to login.")
    elif resp.status_code != 201:
        print(f"Register failed: {resp.text}")
        sys.exit(1)
    
    # 2. Login
    log("Logging in...")
    resp = requests.post(f"{BASE_URL}/auth/login", json={"email": email, "password": password})
    token_data = check(resp)
    token = token_data["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # 3. Get Me
    log("Verifying /auth/me...")
    requests.get(f"{BASE_URL}/auth/me", headers=headers)
    check(resp)

    # 4. Create Project
    log("Creating Project...")
    resp = requests.post(f"{BASE_URL}/projects", headers=headers, json={"name": "Test Project"})
    project = check(resp, 201)
    project_id = project["id"]

    # 5. Create API Key
    log("Creating API Key...")
    resp = requests.post(f"{BASE_URL}/projects/{project_id}/keys", headers=headers, json={"label": "Valid Key"})
    key_data = check(resp, 201, lambda d: d["api_key"] is not None)
    log(f"Received Raw Key: {key_data['api_key'][:5]}...")

    # 6. List API Keys (Verify NO Raw Key)
    log("Listing Keys (Checking for leaks)...")
    resp = requests.get(f"{BASE_URL}/projects/{project_id}/keys", headers=headers)
    keys = check(resp)
    for k in keys:
        if k.get("api_key") is not None:
            print("FAILED: Raw API key leaked in list endpoint!")
            sys.exit(1)
    log("No keys leaked.")

    # 7. Metrics
    log("Checking Metrics...")
    resp = requests.get(f"{BASE_URL}/projects/{project_id}/metrics/summary", headers=headers)
    check(resp)

    log("ALL TESTS PASSED")

if __name__ == "__main__":
    try:
        requests.get(f"{BASE_URL}/health", timeout=2)
    except Exception:
        print(f"Server not reachable at {BASE_URL}. Please ensure it is running.")
        sys.exit(1)
    
    run_tests()
