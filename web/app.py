import logging
import os
import json
import requests
from datetime import datetime, timezone, timedelta
from flask import Flask, render_template, request, redirect, session, url_for, jsonify
from azure.cosmos import CosmosClient

app = Flask(__name__, template_folder='templates')
app.secret_key = os.urandom(24)

# --- GitHub & Databricks Configuration ---
GITHUB_CLIENT_ID = os.environ.get('GITHUB_CLIENT_ID')
GITHUB_CLIENT_SECRET = os.environ.get('GITHUB_CLIENT_SECRET')

raw_host = os.environ.get("DATABRICKS_HOST", "")
DATABRICKS_HOST = raw_host.split('?')[0].strip('/') if raw_host else ""
DATABRICKS_TOKEN = os.environ.get("DATABRICKS_TOKEN")

MODEL_ENDPOINT_PATH = "/serving-endpoints/fake-model-api/invocations"
GITHUB_API_URL = "https://api.github.com"

# --- Cosmos DB ---
COSMOS_CONN_STR = os.environ.get('COSMOS_DB_CONNECTION_STRING')
DATABASE_NAME = 'ProjectGuardianDB'
CONTAINER_NAME = 'Dependencies'
EVENTS_CONTAINER_NAME = 'OssEvents'

cosmos_client = CosmosClient.from_connection_string(COSMOS_CONN_STR)
database = cosmos_client.get_database_client(DATABASE_NAME)
deps_container = database.get_container_client(CONTAINER_NAME)
try:
    events_container = database.create_container_if_not_exists(id=EVENTS_CONTAINER_NAME, partition_key={'paths': ['/repo_full_name']})
except Exception:
    events_container = database.get_container_client(EVENTS_CONTAINER_NAME)


# --- Feature Extraction & Model Invocation ---
SENSITIVE_PATHS = [".github/workflows/", "config/", "secret", "credential", "token", "key", ".env", "password"]
DEPENDENCY_FILES = ["requirements.txt", "package.json", "pom.xml", "build.gradle", "go.mod", "Cargo.toml"]

def get_commit_details(commit_url: str, headers: dict) -> dict:
    try:
        res = requests.get(commit_url, headers=headers, timeout=10)
        if res.status_code == 200:
            return res.json()
    except requests.RequestException:
        pass
    return {}

def extract_features_from_event(event: dict, access_token: str) -> dict | None:
    if event.get('type') != 'PushEvent':
        return None
    payload = event.get('payload', {})
    features = {}
    headers = {'Authorization': f'token {access_token}', 'Accept': 'application/vnd.github.v3+json'}
    try:
        dt_utc = datetime.fromisoformat(event.get('created_at').replace('Z', '+00:00'))
        features['hour_of_day'] = dt_utc.hour
        features['dow'] = dt_utc.weekday()
        features['event_type'] = event.get('type')
        features['action'] = payload.get('action', 'pushed')
        features['repo_name'] = event.get('repo', {}).get('name').split('/')[-1]
        commits = payload.get('commits', [])
        features['commit_count'] = len(commits)
        features['msg_len_avg'] = sum(len(c.get('message', '')) for c in commits) / len(commits) if commits else 0
        touched_sensitive = 0
        dep_changed = 0
        for commit_info in commits[:5]: # 너무 많은 커밋 분석을 방지하기 위해 최대 5개로 제한
            commit_details = get_commit_details(commit_info.get('url'), headers)
            files = commit_details.get('files', [])
            for f in files:
                filename = f.get('filename', '').lower()
                if any(p in filename for p in SENSITIVE_PATHS):
                    touched_sensitive = 1
                if any(d in filename for d in DEPENDENCY_FILES):
                    dep_changed = 1
        features['touched_sensitive_paths'] = touched_sensitive
        features['dep_change_cnt'] = dep_changed
        features['force_push'] = 1 if payload.get('forced', False) else 0
        return features
    except Exception as e:
        logging.error(f"Feature extraction failed: {e}")
        return None

def get_anomaly_score(features: dict) -> float | None:
    if not DATABRICKS_HOST or not DATABRICKS_TOKEN:
        logging.warning("Databricks HOST or TOKEN not set. Returning demo score 0.5.")
        return 0.5
    url = f"{DATABRICKS_HOST}{MODEL_ENDPOINT_PATH}"
    headers = {'Authorization': f'Bearer {DATABRICKS_TOKEN}', 'Content-Type': 'application/json'}
    data_for_model = {"dataframe_records": [features]}
    data = json.dumps(data_for_model)
    try:
        response = requests.post(url, headers=headers, data=data, timeout=20)
        response.raise_for_status()
        predictions = response.json().get('predictions')
        if predictions and isinstance(predictions, list) and len(predictions) > 0:
            logging.info(f"Score from model: {predictions[0]}")
            return predictions[0]
        else:
            logging.error(f"Unexpected format from model: {response.json()}")
            raise ValueError("Invalid model response format")
    except requests.exceptions.RequestException as e:
        logging.error(f"Model invocation failed: {e}")
        raise
    except (json.JSONDecodeError, ValueError) as e:
        logging.error(f"Model response parsing failed: {e} - Response: {response.text}")
        raise

def sync_and_analyze_repo(repo_full_name: str, access_token: str):
    headers = {'Authorization': f'token {access_token}', 'Accept': 'application/vnd.github.v3+json'}
    logging.info(f"Fetching events for {repo_full_name}...")
    events_url = f"{GITHUB_API_URL}/repos/{repo_full_name}/events?per_page=10"
    
    try:
        res = requests.get(events_url, headers=headers, timeout=15)
        res.raise_for_status() # 4xx, 5xx 에러 시 예외 발생
        events = res.json()
    except requests.exceptions.RequestException as e:
        logging.error(f"Failed to fetch events for {repo_full_name}: {e}")
        error_message = f"GitHub API Error: {e}"
        if e.response is not None:
             error_message = f"GitHub API Error (Status {e.response.status_code}): Repository not found or private."
        raise IOError(error_message)

    latest_push_event = next((event for event in events if event['type'] == 'PushEvent'), None)
    
    if not latest_push_event:
        logging.info(f"No recent push event for {repo_full_name}")
        event_doc = {'id': repo_full_name, 'repo_full_name': repo_full_name, 'has_recent_event': False, 'last_synced': datetime.utcnow().isoformat() + 'Z'}
        events_container.upsert_item(body=event_doc)
        return event_doc

    features = extract_features_from_event(latest_push_event, access_token)
    if features:
        score = get_anomaly_score(features)
        event_doc = {
            'id': repo_full_name, 'repo_full_name': repo_full_name, 'has_recent_event': True,
            'event_id': latest_push_event['id'], 'event_type': latest_push_event['type'],
            'created_at': latest_push_event['created_at'], 'actor': latest_push_event.get('actor', {}).get('login'),
            'commits': latest_push_event.get('payload', {}).get('commits', []), 'anomaly_score': score,
            'features': features, 'last_synced': datetime.utcnow().isoformat() + 'Z'
        }
        events_container.upsert_item(body=event_doc)
        logging.info(f"Analysis complete for {repo_full_name}. Score: {score}")
        return event_doc
    
    raise ValueError("Feature extraction failed for the latest event.")

@app.route('/get_oss_activity/<path:repo_name>')
def get_oss_activity(repo_name):
    if 'access_token' not in session:
        return jsonify({"error": "Unauthorized"}), 401
    
    access_token = session.get('access_token')
    try:
        result = sync_and_analyze_repo(repo_name, access_token)
        return jsonify(result)
    except Exception as e:
        # 클라이언트에 보여줄 상세한 에러 메시지 반환
        return jsonify({"error": str(e)}), 500

# --- 로그인 및 SBOM 동기화 로직 (이전과 동일) ---
@app.route('/')
def index():
    if 'access_token' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/login')
def login():
    scope = "repo read:user"
    return redirect(f"https://github.com/login/oauth/authorize?client_id={GITHUB_CLIENT_ID}&scope={scope}")

@app.route('/callback')
def callback():
    session_code = request.args.get('code')
    token_params = { 'client_id': GITHUB_CLIENT_ID, 'client_secret': GITHUB_CLIENT_SECRET, 'code': session_code }
    headers = {'Accept': 'application/json'}
    token_res = requests.post("https://github.com/login/oauth/access_token", params=token_params, headers=headers)
    token_json = token_res.json()
    access_token = token_json.get('access_token')
    if not access_token:
        return "Error: Could not retrieve access token.", 400
    session['access_token'] = access_token
    user_headers = {'Authorization': f'token {access_token}'}
    user_res = requests.get(f"{GITHUB_API_URL}/user", headers=user_headers)
    user_info = user_res.json()
    session['user_id'] = user_info.get('login')
    sync_my_repos_to_db(user_info.get('login'), access_token)
    return redirect(url_for('dashboard'))

def sync_my_repos_to_db(user_id, access_token):
    headers = {'Authorization': f'token {access_token}', 'Accept': 'application/vnd.github+json'}
    repos_res = requests.get(f"{GITHUB_API_URL}/user/repos?type=owner&per_page=100", headers=headers)
    repos = repos_res.json() if repos_res.ok else []
    for repo in repos:
        repo_name = repo.get('name')
        repo_full_name = repo.get('full_name')
        if not repo_full_name: continue
        sbom_url = f"{GITHUB_API_URL}/repos/{repo_full_name}/dependency-graph/sbom"
        sbom_res = requests.get(sbom_url, headers=headers)
        dependencies = set()
        if sbom_res.status_code == 200:
            sbom = sbom_res.json().get('sbom', {})
            for pkg in sbom.get('packages', []):
                pkg_name = pkg.get('name', '')
                if not pkg_name or repo_name.lower() in pkg_name.lower():
                    continue
                version = pkg.get('versionInfo', '')
                repo_path = next((ext_ref.get('locator') for ext_ref in pkg.get('externalRefs', []) if ext_ref.get('referenceType') == 'vcs' and 'github.com' in ext_ref.get('locator', '')), None)
                if repo_path:
                    repo_full_name_dep = '/'.join(repo_path.split('github.com/')[1].replace('.git', '').split('/')[:2])
                    dependencies.add(f"{repo_full_name_dep} {version}".strip())
                else:
                    dependencies.add(f"{pkg_name} {version}".strip())
        item = {
            'id': f"{user_id}_{repo_name}", 'userId': user_id,
            'repositoryName': repo_full_name,
            'lastUpdated': datetime.utcnow().isoformat() + 'Z',
            'dependencies': sorted(list(dependencies))
        }
        deps_container.upsert_item(body=item)

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('index'))
    user_id = session['user_id']
    query = "SELECT * FROM c WHERE c.userId = @userId ORDER BY c.lastUpdated DESC"
    items = list(deps_container.query_items(query, parameters=[{"name": "@userId", "value": user_id}], enable_cross_partition_query=True))
    return render_template('dashboard.html', user_id=user_id, items=items)

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=True)