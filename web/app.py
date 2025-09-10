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
DATABRICKS_HOST = "https://adb-1505442256189071.11.azuredatabracks.net"
DATABRICKS_TOKEN = os.environ.get("DATABRICKS_TOKEN")
# [수정] 요청하신 Fake 모델 엔드포인트 경로로 변경
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
    """개별 커밋 URL을 호출하여 상세 파일 변경 내역을 가져옵니다."""
    try:
        res = requests.get(commit_url, headers=headers)
        if res.status_code == 200:
            return res.json()
    except requests.RequestException:
        pass
    return {}

def extract_features_from_event(event: dict, access_token: str) -> dict | None:
    """[수정] GitHub Push 이벤트에서 10가지 피처를 최대한 상세하게 추출합니다."""
    if event.get('type') != 'PushEvent':
        return None

    payload = event.get('payload', {})
    features = {}
    headers = {'Authorization': f'token {access_token}', 'Accept': 'application/vnd.github.v3+json'}

    try:
        dt_utc = datetime.fromisoformat(event.get('created_at').replace('Z', '+00:00'))
        
        # 1. hour_of_day, 2. dow (Day of Week)
        features['hour_of_day'] = dt_utc.hour
        features['dow'] = dt_utc.weekday()
        
        # 3. event_type, 4. action
        features['event_type'] = event.get('type')
        features['action'] = payload.get('action', 'pushed') # PushEvent는 action 필드가 없어 'pushed'로 고정
        
        # 5. repo_name
        features['repo_name'] = event.get('repo', {}).get('name').split('/')[-1]

        commits = payload.get('commits', [])
        # 6. commit_count
        features['commit_count'] = len(commits)
        # 7. msg_len_avg
        features['msg_len_avg'] = sum(len(c.get('message', '')) for c in commits) / len(commits) if commits else 0

        touched_sensitive = 0
        dep_changed = 0

        # [상세 분석] 각 커밋의 상세 정보를 API로 추가 조회
        for commit_info in commits:
            commit_details = get_commit_details(commit_info.get('url'), headers)
            files = commit_details.get('files', [])
            for f in files:
                filename = f.get('filename', '').lower()
                if any(p in filename for p in SENSITIVE_PATHS):
                    touched_sensitive = 1
                if any(d in filename for d in DEPENDENCY_FILES):
                    dep_changed = 1
        
        # 8. touched_sensitive_paths, 9. dep_change_cnt
        features['touched_sensitive_paths'] = touched_sensitive
        features['dep_change_cnt'] = dep_changed
        
        # 10. force_push
        features['force_push'] = 1 if payload.get('forced', False) else 0

        return features
    except Exception as e:
        logging.error(f"Feature extraction failed: {e}")
        return None

def get_anomaly_score(features: dict) -> float | None:
    """[수정] 피처로 Fake 모델을 호출하여 이상치 점수를 받습니다."""
    if not DATABRICKS_HOST or not DATABRICKS_TOKEN:
        logging.warning("Databricks 호스트 또는 토큰이 설정되지 않았습니다. 데모 점수(0.5)를 반환합니다.")
        return 0.5

    url = f"{DATABRICKS_HOST}{MODEL_ENDPOINT_PATH}"
    headers = {'Authorization': f'Bearer {DATABRICKS_TOKEN}', 'Content-Type': 'application/json'}
    
    # 모델 입력 형식에 맞게 데이터 프레임 레코드로 변환
    data_for_model = {
        "dataframe_records": [features]
    }
    data = json.dumps(data_for_model)

    try:
        response = requests.post(url, headers=headers, data=data, timeout=20)
        response.raise_for_status() # 200이 아닌 경우 예외 발생
        # Fake 모델은 보통 {'predictions': [0.5]} 와 같은 형태로 응답
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
    """[신규] 단일 리포지토리의 최신 이벤트를 분석하고 DB에 저장하는 함수"""
    headers = {'Authorization': f'token {access_token}', 'Accept': 'application/vnd.github.v3+json'}
    logging.info(f"{repo_full_name}의 이벤트 가져오는 중...")
    events_url = f"{GITHUB_API_URL}/repos/{repo_full_name}/events?per_page=10"
    res = requests.get(events_url, headers=headers)

    if res.status_code != 200:
        logging.error(f"{repo_full_name}의 이벤트 가져오기 실패: {res.text}")
        return None

    latest_push_event = next((event for event in res.json() if event['type'] == 'PushEvent'), None)

    if not latest_push_event:
        logging.info(f"{repo_full_name}에 최근 Push 이벤트 없음")
        # 데이터가 없다는 사실을 DB에 기록
        event_doc = {
            'id': repo_full_name,
            'repo_full_name': repo_full_name,
            'has_recent_event': False,
            'last_synced': datetime.utcnow().isoformat() + 'Z'
        }
        events_container.upsert_item(body=event_doc)
        return event_doc

    features = extract_features_from_event(latest_push_event, access_token)
    if features:
        score = get_anomaly_score(features)
        
        event_doc = {
            'id': repo_full_name, # 파티션 키와 동일하게 ID 설정하여 덮어쓰기
            'repo_full_name': repo_full_name,
            'has_recent_event': True,
            'event_id': latest_push_event['id'],
            'event_type': latest_push_event['type'],
            'created_at': latest_push_event['created_at'],
            'actor': latest_push_event.get('actor', {}).get('login'),
            'commits': latest_push_event.get('payload', {}).get('commits', []),
            'anomaly_score': score,
            'features': features,
            'last_synced': datetime.utcnow().isoformat() + 'Z'
        }
        events_container.upsert_item(body=event_doc)
        logging.info(f"{repo_full_name} 분석 완료. 점수: {score}")
        return event_doc
    return None

# --- Routes ---

# [신규] 의존성 클릭 시 비동기(AJAX)로 호출될 API 엔드포인트
@app.route('/get_oss_activity/<path:repo_name>')
def get_oss_activity(repo_name):
    if 'access_token' not in session:
        return jsonify({"error": "Unauthorized"}), 401

    access_token = session.get('access_token')
    
    # 1. DB에서 먼저 찾아봄
    try:
        item = events_container.read_item(item=repo_name, partition_key=repo_name)
        # 1시간 이상 지났으면 새로고침
        last_synced = datetime.fromisoformat(item['last_synced'].replace('Z', '+00:00'))
        if datetime.now(timezone.utc) - last_synced > timedelta(hours=1):
             raise Exception("Stale data, refresh")
        return jsonify(item)
    except Exception:
        # DB에 없거나 오래됐으면 실시간으로 GitHub API 호출하여 분석 및 저장
        result = sync_and_analyze_repo(repo_name, access_token)
        if result:
            return jsonify(result)
        else:
            return jsonify({"error": "Failed to fetch activity"}), 500

# 기존 라우트들은 유지 (로그인, 콜백, 로그아웃 등)
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
    # ... 기존 콜백 로직 ...
    # 이 부분은 수정하지 않았습니다.
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
    
    # 최초 로그인 시 내 레포지토리 목록 동기화 (기존 로직)
    sync_my_repos_to_db(user_info.get('login'), access_token)

    return redirect(url_for('dashboard'))

def sync_my_repos_to_db(user_id, access_token):
    # 이 함수는 사용자의 레포지토리와 그 의존성을 SBOM으로 가져와
    # 'Dependencies' 컨테이너에 저장하는 기존 로직입니다.
    # 이 부분도 수정하지 않았습니다.
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
                name = pkg.get('name', '')
                version = pkg.get('versionInfo', '')
                # 'owner/repo' 형식의 이름을 찾기 위한 추가 로직 (예시)
                repo_path = next((ext_ref.get('locator') for ext_ref in pkg.get('externalRefs', []) if ext_ref.get('referenceCategory') == 'PACKAGE-MANAGER' and 'github.com' in ext_ref.get('locator', '')), None)
                if repo_path and 'github.com/' in repo_path:
                    repo_full_name_dep = '/'.join(repo_path.split('github.com/')[1].split('/')[:2])
                    dependencies.append(f"{repo_full_name_dep} {version}".strip())
                elif name and repo_name and repo_name.lower() not in name.lower():
                    dependencies.append(f"{name} {version}".strip())
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