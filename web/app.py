from flask import Flask, render_template, request, redirect, session, url_for
import requests
import os
from azure.cosmos import CosmosClient
from datetime import datetime, timedelta, timezone

app = Flask(__name__, template_folder='templates')
app.secret_key = os.urandom(24)

# --- GitHub OAuth App ---
GITHUB_CLIENT_ID = os.environ.get('GITHUB_CLIENT_ID')
GITHUB_CLIENT_SECRET = os.environ.get('GITHUB_CLIENT_SECRET')
GITHUB_API_URL = "https://api.github.com"

# --- Cosmos DB ---
COSMOS_CONN_STR = os.environ.get('COSMOS_DB_CONNECTION_STRING')
DATABASE_NAME = 'ProjectGuardianDB'
CONTAINER_NAME = 'Dependencies'

cosmos_client = CosmosClient.from_connection_string(COSMOS_CONN_STR)
database = cosmos_client.get_database_client(DATABASE_NAME)
container = database.get_container_client(CONTAINER_NAME)

# ---- 시간대: KST 변환 (서버 저장은 계속 UTC) ----
KST = timezone(timedelta(hours=9))
def utc_to_kst(utc_str: str) -> str:
    if not utc_str:
        return utc_str
    try:
        raw = utc_str[:-1] if utc_str.endswith('Z') else utc_str
        try:
            dt = datetime.strptime(raw, "%Y-%m-%dT%H:%M:%S.%f")
        except ValueError:
            dt = datetime.strptime(raw, "%Y-%m-%dT%H:%M:%S")
        return dt.replace(tzinfo=timezone.utc).astimezone(KST).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return utc_str

app.jinja_env.filters['to_kst'] = utc_to_kst

# --- Routes ---
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
    token_params = {
        'client_id': GITHUB_CLIENT_ID,
        'client_secret': GITHUB_CLIENT_SECRET,
        'code': session_code
    }
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
    return redirect(url_for('dashboard'))

def sync_github_to_cosmos(user_id, access_token):
    """사용자 리포지토리 SBOM에서 의존성 추출하여 Cosmos DB upsert."""
    if not access_token:
        return
    headers = {'Authorization': f'token {access_token}', 'Accept': 'application/vnd.github+json'}
    repos_res = requests.get(f"{GITHUB_API_URL}/user/repos?type=owner&per_page=100", headers=headers)
    repos = repos_res.json() if repos_res.ok else []

    for repo in repos:
        repo_name = repo.get('name')
        repo_full_name = repo.get('full_name')
        if not repo_full_name:
            continue

        sbom_url = f"{GITHUB_API_URL}/repos/{repo_full_name}/dependency-graph/sbom"
        sbom_res = requests.get(sbom_url, headers=headers)

        dependencies = []
        if sbom_res.status_code == 200:
            sbom = sbom_res.json().get('sbom', {})
            for pkg in sbom.get('packages', []):
                name = pkg.get('name', '')
                version = pkg.get('versionInfo', '')
                if name and repo_name and repo_name.lower() not in name.lower():
                    dependencies.append(f"{name} {version}".strip())

        item = {
            'id': f"{user_id}_{repo_name}",
            'userId': user_id,
            'repositoryName': repo_full_name,         # "owner/name"
            'lastUpdated': datetime.utcnow().isoformat() + 'Z',  # UTC 저장
            'dependencies': sorted(dependencies)
        }
        container.upsert_item(body=item)

@app.route('/dashboard')
def dashboard():
    """DB 조회, 없으면 동기화 후 항목 전달 (좌: 레포, 우: 선택 레포 의존성)."""
    if 'user_id' not in session:
        return redirect(url_for('index'))

    user_id = session['user_id']

    query = "SELECT * FROM c WHERE c.userId = @userId"
    items = list(container.query_items(
        query=query,
        parameters=[{"name": "@userId", "value": user_id}],
        enable_cross_partition_query=True
    ))

    if not items:
        sync_github_to_cosmos(user_id, session.get('access_token'))
        items = list(container.query_items(
            query=query,
            parameters=[{"name": "@userId", "value": user_id}],
            enable_cross_partition_query=True
        ))

    # 최신순 정렬(최근 업데이트가 위로)
    items.sort(key=lambda x: x.get('lastUpdated', ''), reverse=True)

    return render_template('dashboard.html', user_id=user_id, items=items)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=True)
