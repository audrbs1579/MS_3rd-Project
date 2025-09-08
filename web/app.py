from flask import Flask, render_template, request, redirect, session, url_for
import requests
import os
from azure.cosmos import CosmosClient, PartitionKey

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

# --- GitHub 로그인 관련 라우트 ---
# 이전과 동일 (생략)
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
        # 사용자 정보 가져와서 세션에 저장
        user_headers = {'Authorization': f'token {access_token}'}
        user_res = requests.get(f"{GITHUB_API_URL}/user", headers=user_headers)
        user_info = user_res.json()
        session['user_id'] = user_info.get('login')
        return redirect(url_for('dashboard'))
    else:
        return "Error: Could not retrieve access token.", 400

# --- 핵심 기능: 대시보드 및 데이터 동기화 ---
@app.route('/dashboard')
def dashboard():
    """DB에서 데이터를 조회하고, 없으면 GitHub에서 가져와 동기화합니다."""
    if 'user_id' not in session:
        return redirect(url_for('index'))
    
    user_id = session['user_id']
    
    # 1. Cosmos DB에서 현재 사용자의 데이터 조회
    query = "SELECT * FROM c WHERE c.userId = @userId"
    items = list(container.query_items(
        query=query,
        parameters=[{"name": "@userId", "value": user_id}],
        enable_cross_partition_query=True
    ))
    
    # 2. DB에 데이터가 없으면 GitHub에서 동기화 실행
    if not items:
        # 동기화 함수 호출 (시간이 걸릴 수 있음)
        sync_github_to_cosmos(user_id, session.get('access_token'))
        # 동기화 후 다시 데이터 조회
        items = list(container.query_items(
            query=query,
            parameters=[{"name": "@userId", "value": user_id}],
            enable_cross_partition_query=True
        ))
        
    return render_template('dashboard.html', user_id=user_id, items=items)

def sync_github_to_cosmos(user_id, access_token):
    """사용자의 모든 리포지토리 의존성을 GitHub에서 가져와 Cosmos DB에 저장합니다."""
    if not access_token:
        return

    headers = {'Authorization': f'token {access_token}', 'Accept': 'application/vnd.github+json'}
    
    # 1. 사용자의 모든 리포지토리 목록 가져오기
    repos_res = requests.get(f"{GITHUB_API_URL}/user/repos?type=owner", headers=headers)
    repos = repos_res.json()

    # 2. 각 리포지토리의 의존성 분석 및 DB에 저장
    for repo in repos:
        repo_name = repo.get('name')
        repo_full_name = repo.get('full_name')
        
        sbom_url = f"{GITHUB_API_URL}/repos/{repo_full_name}/dependency-graph/sbom"
        sbom_res = requests.get(sbom_url, headers=headers)
        
        dependencies = []
        if sbom_res.status_code == 200:
            sbom_data = sbom_res.json().get('sbom', {})
            packages = sbom_data.get('packages', [])
            for pkg in packages:
                name = pkg.get('name', '')
                version = pkg.get('versionInfo', '')
                if name and repo_name.lower() not in name.lower():
                    dependencies.append(f"{name} {version}".strip())
        
        # 3. Cosmos DB에 저장할 데이터 구조 만들기
        item_body = {
            'id': f"{user_id}_{repo_name}",
            'userId': user_id,
            'repositoryName': repo_full_name,
            'lastUpdated': datetime.utcnow().isoformat() + 'Z',
            'dependencies': sorted(dependencies)
        }
        
        # 4. Upsert (있으면 업데이트, 없으면 생성)
        container.upsert_item(body=item_body)
    
    return