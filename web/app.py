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

# [수정] HOST 값에서 불필요한 부분을 제거하도록 처리
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
        res = requests.get(commit_url, headers=headers)
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
        for commit_info in commits:
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
        logging.warning("Databricks 호스트 또는 토큰이 설정되지 않았습니다. 데모 점수(0.5)를 반환합니다.")
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
            logging.info(f"모델로부터 받은 점수: {predictions[0]}")
            return predictions[0]
        else:
            logging.error(f"모델 응답에서 예상치 못한 형식: {response.json()}")
            return None
    except requests.exceptions.RequestException as e:
        logging.error(f"모델 호출 실패: {e}")
        return None
    except json.JSONDecodeError as e:
        logging.error(f"모델 응답 JSON 파싱 실패: {e} - 응답 내용: {response.text}")
        return None

def sync_and_analyze_repo(repo_full_name: str, access_token: str):
    headers = {'Authorization': f'token {access_token}', 'Accept': 'application/vnd.github.v3+json'}
    logging.info(f"{repo_full_name}의 이벤트 가져오는 중...")
    events_url = f"{GITHUB_API_URL}/repos/{repo_full_name}/events?per_page=10"
    res = requests.get(events_url, headers=headers)
    if res.status_code != 200:
        logging.error(f"{repo_full_name}의 이벤트 가져오기 실패: {res.text}")
        # 404 에러 등을 DB에 기록하여 클라이언트에 전달
        event_doc = {'id': repo_full_name, 'repo_full_name': repo_full_name, 'has_recent_event': False, 'error': 'Repository not found or private.', 'last_synced': datetime.utcnow().isoformat() + 'Z'}
        events_container.upsert_item(body=event_doc)
        return event_doc
        
    latest_push_event = next((event for event in res.json() if event['type'] == 'PushEvent'), None)
    if not latest_push_event:
        logging.info(f"{repo_full_name}에 최근 Push 이벤트 없음")
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
        logging.info(f"{repo_full_name} 분석 완료. 점수: {score}")
        return event_doc
    return None

@app.route('/get_oss_activity/<path:repo_name>')
def get_oss_activity(repo_name):
    if 'access_token' not in session:
        return jsonify({"error": "Unauthorized"}), 401
    access_token = session.get('access_token')
    try:
        item = events_container.read_item(item=repo_name, partition_key=repo_name)
        last_synced = datetime.fromisoformat(item['last_synced'].replace('Z', '+00:00'))
        if datetime.now(timezone.utc) - last_synced > timedelta(hours=1):
             raise Exception("Stale data, refresh")
        return jsonify(item)
    except Exception:
        result = sync_and_analyze_repo(repo_name, access_token)
        if result:
            return jsonify(result)
        else:
            error_payload = {"error": f"Failed to fetch or analyze activity for {repo_name}."}
            return jsonify(error_payload), 500

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
        dependencies = []
        if sbom_res.status_code == 200:
            sbom = sbom_res.json().get('sbom', {})
            for pkg in sbom.get('packages', []):
                version = pkg.get('versionInfo', '')
                repo_path = next((ext_ref.get('locator') for ext_ref in pkg.get('externalRefs', []) if ext_ref.get('referenceType') == 'vcs' and 'github.com' in ext_ref.get('locator', '')), None)
                if repo_path:
                    repo_full_name_dep = '/'.join(repo_path.split('github.com/')[1].replace('.git', '').split('/')[:2])
                    dependencies.append(f"{repo_full_name_dep} {version}".strip())
        item = {
            'id': f"{user_id}_{repo_name}", 'userId': user_id,
            'repositoryName': repo_full_name,
            'lastUpdated': datetime.utcnow().isoformat() + 'Z',
            'dependencies': sorted(list(set(dependencies)))
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