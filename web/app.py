import logging
import os
import json
import requests
from datetime import datetime, timezone, timedelta
from flask import Flask, render_template, request, redirect, session, url_for, jsonify
from azure.cosmos import CosmosClient
from azure.cosmos.exceptions import CosmosResourceNotFoundError

app = Flask(__name__, template_folder='templates')
app.secret_key = os.urandom(24)

# --- Configuration ---
GITHUB_CLIENT_ID = os.environ.get('GITHUB_CLIENT_ID')
GITHUB_CLIENT_SECRET = os.environ.get('GITHUB_CLIENT_SECRET')
raw_host = os.environ.get("DATABRICKS_HOST", "")
DATABRICKS_HOST = raw_host.split('?')[0].strip('/') if raw_host else ""
DATABRICKS_TOKEN = os.environ.get("DATABRICKS_TOKEN")
MODEL_ENDPOINT_PATH = "/serving-endpoints/fake-model-api/invocations"
GITHUB_API_URL = "https://api.github.com"
COSMOS_CONN_STR = os.environ.get('COSMOS_DB_CONNECTION_STRING')
DATABASE_NAME = 'ProjectGuardianDB'
DEPS_CONTAINER_NAME = 'Dependencies'
EVENTS_CONTAINER_NAME = 'leases'

# --- Cosmos DB Initialization ---
try:
    cosmos_client = CosmosClient.from_connection_string(COSMOS_CONN_STR)
    database = cosmos_client.get_database_client(DATABASE_NAME)
    deps_container = database.get_container_client(DEPS_CONTAINER_NAME)
    events_container = database.get_container_client(EVENTS_CONTAINER_NAME)
    logging.info("Cosmos DB에 성공적으로 연결되었습니다.")
except Exception as e:
    logging.critical(f"Cosmos DB 연결 실패: {e}")
    cosmos_client = database = deps_container = events_container = None

# --- Feature Extraction & Model Invocation ---
SENSITIVE_PATHS = [".github/workflows/", "config/", "secret", "credential", "token", "key", ".env", "password"]
DEPENDENCY_FILES = ["requirements.txt", "package.json", "pom.xml", "build.gradle", "go.mod", "Cargo.toml"]

def get_commit_details(commit_url: str, headers: dict) -> dict:
    try:
        res = requests.get(commit_url, headers=headers, timeout=10)
        return res.json() if res.status_code == 200 else {}
    except requests.RequestException:
        return {}

def extract_features_from_event(event: dict, access_token: str) -> dict | None:
    if event.get('type') != 'PushEvent': return None
    payload = event.get('payload', {})
    features, headers = {}, {'Authorization': f'token {access_token}', 'Accept': 'application/vnd.github.v3+json'}
    try:
        dt_utc = datetime.fromisoformat(event['created_at'].replace('Z', '+00:00'))
        features.update({
            'hour_of_day': dt_utc.hour, 'dow': dt_utc.weekday(),
            'event_type': event['type'], 'action': 'pushed',
            'repo_name': event['repo']['name'].split('/')[-1],
            'commit_count': len(payload.get('commits', [])),
            'msg_len_avg': sum(len(c.get('message', '')) for c in payload.get('commits', [])) / len(payload.get('commits', [])) if payload.get('commits') else 0,
            'force_push': 1 if payload.get('forced') else 0
        })
        touched_sensitive, dep_changed = 0, 0
        for commit_info in payload.get('commits', [])[:5]:
            files = get_commit_details(commit_info.get('url'), headers).get('files', [])
            for f in files:
                filename = f.get('filename', '').lower()
                if any(p in filename for p in SENSITIVE_PATHS): touched_sensitive = 1
                if any(d in filename for d in DEPENDENCY_FILES): dep_changed = 1
        features.update({'touched_sensitive_paths': touched_sensitive, 'dep_change_cnt': dep_changed})
        return features
    except Exception as e:
        logging.error(f"Feature extraction failed: {e}")
        return None

def get_anomaly_score(features: dict) -> float | None:
    if not DATABRICKS_HOST or not DATABRICKS_TOKEN: return 0.5
    url, headers = f"{DATABRICKS_HOST}{MODEL_ENDPOINT_PATH}", {'Authorization': f'Bearer {DATABRICKS_TOKEN}', 'Content-Type': 'application/json'}
    data = json.dumps({"dataframe_records": [features]})
    try:
        response = requests.post(url, headers=headers, data=data, timeout=20)
        response.raise_for_status()
        predictions = response.json().get('predictions')
        if predictions and isinstance(predictions, list) and predictions:
            # [수정] 모델이 반환한 값이 숫자인지 확인하여 안정성 강화
            prediction = predictions[0]
            if isinstance(prediction, (int, float)):
                return float(prediction)
            else:
                logging.warning(f"Model returned a non-numeric prediction: {prediction}")
                return None # 숫자가 아니면 None 반환
        raise ValueError("Invalid model response format")
    except Exception as e:
        logging.error(f"Model invocation failed: {e}")
        # 실패 시 예외를 발생시키는 대신 None을 반환하여 앱 중단 방지
        return None

def sync_and_analyze_repo(repo_full_name: str, access_token: str):
    safe_id = repo_full_name.replace('/', '_').replace('.', '_')
    headers = {'Authorization': f'token {access_token}', 'Accept': 'application/vnd.github.v3+json'}
    events_url = f"{GITHUB_API_URL}/repos/{repo_full_name}/events?per_page=100"
    
    try:
        res = requests.get(events_url, headers=headers, timeout=15)
        res.raise_for_status()
        events = res.json()
    except requests.exceptions.RequestException as e:
        error_message = f"GitHub API Error (Status {e.response.status_code if e.response else 'N/A'}): Repository '{repo_full_name}' not found or private."
        raise IOError(error_message)
    
    latest_push = next((e for e in events if e['type'] == 'PushEvent'), None)
    
    # [수정] Push 이벤트가 없을 경우, 에러 대신 기본 점수를 부여하여 항상 결과를 표시
    if not latest_push:
        logging.info(f"[{repo_full_name}] No recent PushEvent found. Assigning a low default anomaly score.")
        event_doc = {
            'id': safe_id, 'repo_full_name': repo_full_name, 'has_recent_event': True,
            'event_id': 'N/A', 'event_type': 'NoPushEvent', # 이벤트 없음을 명시하는 타입
            'created_at': datetime.utcnow().isoformat() + 'Z', 'actor': 'System',
            'commits': [{'author': {'name': 'N/A'}, 'message': 'No recent push activity detected.'}],
            'anomaly_score': 0.1, # 기본적으로 낮은 위험 점수 부여
            'features': {}, 'last_synced': datetime.utcnow().isoformat() + 'Z'
        }
        events_container.upsert_item(body=event_doc)
        return event_doc

    features = extract_features_from_event(latest_push, access_token)
    if features:
        score = get_anomaly_score(features)
        event_doc = {
            'id': safe_id, 'repo_full_name': repo_full_name, 'has_recent_event': True,
            'event_id': latest_push['id'], 'event_type': latest_push['type'],
            'created_at': latest_push['created_at'], 'actor': latest_push.get('actor', {}).get('login'),
            'commits': latest_push.get('payload', {}).get('commits', []), 'anomaly_score': score,
            'features': features, 'last_synced': datetime.utcnow().isoformat() + 'Z'
        }
        events_container.upsert_item(body=event_doc)
        return event_doc
    
    # 특징 추출 실패 시에도 앱이 중단되지 않도록 예외 대신 값을 반환
    raise ValueError("Feature extraction failed, but proceeding.")


@app.route('/get_oss_activity/<path:repo_name>')
def get_oss_activity(repo_name):
    if 'access_token' not in session: return jsonify({"error": "Unauthorized"}), 401
    safe_id = repo_name.replace('/', '_').replace('.', '_')
    try:
        query = f"SELECT * FROM c WHERE c.id = '{safe_id}'"
        items = list(events_container.query_items(query, enable_cross_partition_query=True))
        if items:
            item = items[0]
            last_synced = datetime.fromisoformat(item['last_synced'].replace('Z', '+00:00'))
            if datetime.now(timezone.utc) - last_synced > timedelta(hours=1):
                raise CosmosResourceNotFoundError("Stale data, forcing refresh")
            return jsonify(item)
        else:
            return jsonify(sync_and_analyze_repo(repo_name, session['access_token']))
    except CosmosResourceNotFoundError:
        return jsonify(sync_and_analyze_repo(repo_name, session['access_token']))
    except Exception as e:
        logging.error(f"Error in get_oss_activity for {repo_name}: {e}")
        # 실패 시에도 분석을 시도하도록 로직 변경
        try:
            return jsonify(sync_and_analyze_repo(repo_name, session['access_token']))
        except Exception as sync_e:
            return jsonify({"error": str(sync_e)}), 500

@app.route('/sync_my_repos')
def sync_my_repos_route():
    if 'user_id' not in session or 'access_token' not in session:
        return redirect(url_for('index'))
    sync_my_repos_to_db(session['user_id'], session['access_token'])
    return redirect(url_for('dashboard'))

@app.route('/')
def index():
    return redirect(url_for('dashboard')) if 'access_token' in session else render_template('index.html')

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
    token_params = {'client_id': GITHUB_CLIENT_ID, 'client_secret': GITHUB_CLIENT_SECRET, 'code': session_code}
    headers = {'Accept': 'application/json'}
    token_res = requests.post("https://github.com/login/oauth/access_token", params=token_params, headers=headers)
    token_json = token_res.json()
    access_token = token_json.get('access_token')
    if not access_token: return "Error: Could not retrieve access token.", 400
    session['access_token'] = access_token
    user_headers = {'Authorization': f'token {access_token}'}
    user_res = requests.get(f"{GITHUB_API_URL}/user", headers=user_headers)
    user_info = user_res.json()
    session['user_id'] = user_info.get('login')
    sync_my_repos_to_db(user_info.get('login'), access_token)
    return redirect(url_for('dashboard'))

def sync_my_repos_to_db(user_id, access_token):
    if not deps_container: return
    headers = {'Authorization': f'token {access_token}', 'Accept': 'application/vnd.github+json'}
    repos_res = requests.get(f"{GITHUB_API_URL}/user/repos?type=owner&per_page=100", headers=headers)
    repos = repos_res.json() if repos_res.ok else []
    for repo in repos:
        repo_full_name = repo.get('full_name')
        if not repo_full_name: continue
        sbom_url = f"{GITHUB_API_URL}/repos/{repo_full_name}/dependency-graph/sbom"
        sbom_res = requests.get(sbom_url, headers=headers)
        dependencies = set()
        if sbom_res.status_code == 200:
            for pkg in sbom_res.json().get('sbom', {}).get('packages', []):
                pkg_name, repo_name = pkg.get('name', ''), repo.get('name', '')
                if not pkg_name or repo_name.lower() in pkg_name.lower(): continue
                version = pkg.get('versionInfo', '')
                repo_path = next((ref.get('locator') for ref in pkg.get('externalRefs', []) if ref.get('referenceType') == 'vcs' and 'github.com' in ref.get('locator', '')), None)
                if repo_path:
                    repo_full_name_dep = '/'.join(repo_path.split('github.com/')[1].replace('.git', '').split('/')[:2])
                    dependencies.add(f"{repo_full_name_dep} {version}".strip())
                else:
                    dependencies.add(f"{pkg_name} {version}".strip())
        item = {
            'id': f"{user_id}_{repo.get('name')}", 'userId': user_id,
            'repositoryName': repo_full_name,
            'lastUpdated': datetime.utcnow().isoformat() + 'Z',
            'dependencies': sorted(list(dependencies))
        }
        deps_container.upsert_item(body=item)

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session: return redirect(url_for('index'))
    if not deps_container: return "Error: Could not connect to the database.", 500
    user_id = session['user_id']
    query = f"SELECT * FROM c WHERE c.userId = '{user_id}'"
    items = sorted(list(deps_container.query_items(query, enable_cross_partition_query=True)), key=lambda x: x.get('repositoryName', ''))
    return render_template('dashboard.html', user_id=user_id, items=items)

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=True)