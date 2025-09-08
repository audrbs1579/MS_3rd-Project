from flask import Flask, render_template, request, redirect, session, url_for
import requests
import os
from azure.cosmos import CosmosClient
from datetime import datetime, timedelta, timezone

app = Flask(__name__, template_folder='templates')
app.secret_key = os.urandom(24)

# --- GitHub OAuth App 정보 ---
GITHUB_CLIENT_ID = os.environ.get('GITHUB_CLIENT_ID')
GITHUB_CLIENT_SECRET = os.environ.get('GITHUB_CLIENT_SECRET')
GITHUB_API_URL = "https://api.github.com"

# --- Cosmos DB 설정 ---
COSMOS_CONN_STR = os.environ.get('COSMOS_DB_CONNECTION_STRING')
DATABASE_NAME = 'ProjectGuardianDB'
CONTAINER_NAME = 'Dependencies'

# Cosmos DB 클라이언트 초기화
cosmos_client = CosmosClient.from_connection_string(COSMOS_CONN_STR)
database = cosmos_client.get_database_client(DATABASE_NAME)
container = database.get_container_client(CONTAINER_NAME)

# ---- 시간대/필터 (KST 변환) ----
KST = timezone(timedelta(hours=9))

def utc_to_kst(utc_str: str) -> str:
    """
    "2025-09-08T07:47:27.715446Z" 같은 UTC ISO8601 → "YYYY-MM-DD HH:MM:SS" (KST)
    파싱 실패 시 원문을 그대로 반환
    """
    if not utc_str:
        return utc_str
    try:
        # 마이크로초 포함 케이스
        if utc_str.endswith('Z'):
            utc_str = utc_str[:-1]  # 'Z' 제거
        # 마이크로초가 있을 수도/없을 수도 있어 포맷을 2단계로 시도
        try:
            dt = datetime.strptime(utc_str, "%Y-%m-%dT%H:%M:%S.%f")
        except ValueError:
            dt = datetime.strptime(utc_str, "%Y-%m-%dT%H:%M:%S")
        dt = dt.replace(tzinfo=timezone.utc).astimezone(KST)
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return utc_str

# Jinja 필터 등록
app.jinja_env.filters['to_kst'] = utc_to_kst

# --- 기본 라우트 ---
@app.route('/')
def index():
    if 'access_token' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

# --- GitHub 로그인 ---
@app.route('/login')
def login():
    scope = "repo read:user"
    return redirect(f"https://github.com/login/oauth/authorize?client_id={GITHUB_CLIENT_ID}&scope={scope}")

@app.route('/callback')
def callback():
    session_code = request.args.get('code')
    token_params = {
        'client_id': GITHUB_CLIENT_ID,
        'client_secret': GITHUB_CLIENT_SECRET,
        'code': session_code
    }
    headers = {'Accept': 'application/json'}
    token_res = requests.post("https://github.com/login/oauth/access_token", params=token_params, headers=headers)
    token_json = token_res.json()

    access_token = token_json.get('access_token')
    if access_token:
        session['access_token'] = access_token
        # 사용자 정보
        user_headers = {'Authorization': f'token {access_token}'}
        user_res = requests.get(f"{GITHUB_API_URL}/user", headers=user_headers)
        user_info = user_res.json()
        session['user_id'] = user_info.get('login')
        return redirect(url_for('dashboard'))
    else:
        return "Error: Could not retrieve access token.", 400

# --- 동기화 함수 ---
def sync_github_to_cosmos(user_id, access_token):
    """사용자의 모든 리포지토리 의존성을 GitHub에서 가져와 Cosmos DB에 저장"""
    if not access_token:
        return

    headers = {'Authorization': f'token {access_token}', 'Accept': 'application/vnd.github+json'}
    # 1) 사용자 소유 리포 목록
    repos_res = requests.get(f"{GITHUB_API_URL}/user/repos?type=owner&per_page=100", headers=headers)
    repos = repos_res.json() if repos_res.ok else []

    # 2) 각 리포 SBOM → dependencies 저장
    for repo in repos:
        repo_name = repo.get('name')
        repo_full_name = repo.get('full_name')  # owner/name
        if not repo_full_name:
            continue

        sbom_url = f"{GITHUB_API_URL}/repos/{repo_full_name}/dependency-graph/sbom"
        sbom_res = requests.get(sbom_url, headers=headers)

        dependencies = []
        if sbom_res.status_code == 200:
            sbom_data = sbom_res.json().get('sbom', {})
            for pkg in sbom_data.get('packages', []):
                name = pkg.get('name', '')
                version = pkg.get('versionInfo', '')
                if name and repo_name and repo_name.lower() not in name.lower():
                    dependencies.append(f"{name} {version}".strip())

        item_body = {
            'id': f"{user_id}_{repo_name}",
            'userId': user_id,
            'repositoryName': repo_full_name,       # "owner/name"
            'lastUpdated': datetime.utcnow().isoformat() + 'Z',  # UTC 저장
            'dependencies': sorted(dependencies)
        }
        container.upsert_item(body=item_body)

# --- 대시보드 ---
@app.route('/dashboard')
def dashboard():
    """DB에서 데이터 조회. 없으면 GitHub에서 동기화 후 표시."""
    if 'user_id' not in session:
        return redirect(url_for('index'))

    user_id = session['user_id']

    # DB 조회
    query = "SELECT * FROM c WHERE c.userId = @userId"
    items = list(container.query_items(
        query=query,
        parameters=[{"name": "@userId", "value": user_id}],
        enable_cross_partition_query=True
    ))

    # 없으면 동기화
    if not items:
        sync_github_to_cosmos(user_id, session.get('access_token'))
        items = list(container.query_items(
            query=query,
            parameters=[{"name": "@userId", "value": user_id}],
            enable_cross_partition_query=True
        ))

    # 오른쪽 패널(계정 목록) 데이터: repositoryName의 owner를 unique 집합으로
    owners = []
    seen = set()
    for it in items:
        repo_full = it.get('repositoryName', '')
        owner = repo_full.split('/')[0] if '/' in repo_full else user_id
        if owner not in seen:
            owners.append({'owner': owner, 'count': 0})
            seen.add(owner)
    # 각 소유자별 레포 수 카운트
    for it in items:
        owner = (it.get('repositoryName','').split('/')[0] 
                 if '/' in it.get('repositoryName','') else user_id)
        for o in owners:
            if o['owner'] == owner:
                o['count'] += 1
                break

    # 선택된 계정(쿼리 파라미터) — 기본은 전체
    selected_owner = request.args.get('account', 'all')

    return render_template(
        'dashboard.html',
        user_id=user_id,
        items=items,
        owners=owners,
        selected_owner=selected_owner
    )

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=True)
