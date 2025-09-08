from flask import Flask, render_template, request, redirect, session, url_for
import requests
import os

app = Flask(__name__, template_folder='templates')

# Flask 세션을 위한 시크릿 키 설정 (실제 운영 시에는 더 복잡하고 안전한 값으로 변경)
# 터미널에서 python -c 'import os; print(os.urandom(24))' 명령으로 생성 가능
app.secret_key = os.urandom(24) 

# GitHub OAuth App 정보 (실제로는 환경 변수에서 가져와야 함)
# Azure App Service의 '구성' -> '응용 프로그램 설정'에 추가하는 것이 가장 안전합니다.
GITHUB_CLIENT_ID = os.environ.get('GITHUB_CLIENT_ID', 'YOUR_GITHUB_CLIENT_ID')
GITHUB_CLIENT_SECRET = os.environ.get('GITHUB_CLIENT_SECRET', 'YOUR_GITHUB_CLIENT_SECRET')

GITHUB_OAUTH_URL = "https://github.com/login/oauth/authorize"
GITHUB_TOKEN_URL = "https://github.com/login/oauth/access_token"
GITHUB_API_URL = "https://api.github.com"


@app.route('/')
def index():
    """로그인 페이지를 보여줍니다."""
    if 'access_token' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/login')
def login():
    """사용자를 GitHub 인증 페이지로 보냅니다."""
    # repo: private 저장소 접근, read:user: 사용자 정보 읽기 권한
    scope = "repo read:user"
    return redirect(f"{GITHUB_OAUTH_URL}?client_id={GITHUB_CLIENT_ID}&scope={scope}")

@app.route('/callback')
def callback():
    """GitHub에서 인증 후 돌아오는 경로. Access Token을 발급받습니다."""
    session_code = request.args.get('code')
    
    token_params = {
        'client_id': GITHUB_CLIENT_ID,
        'client_secret': GITHUB_CLIENT_SECRET,
        'code': session_code
    }
    headers = {'Accept': 'application/json'}
    token_res = requests.post(GITHUB_TOKEN_URL, params=token_params, headers=headers)
    token_json = token_res.json()
    
    access_token = token_json.get('access_token')
    
    if access_token:
        session['access_token'] = access_token
        return redirect(url_for('dashboard'))
    else:
        return "Error: Could not retrieve access token.", 400

@app.route('/dashboard')
def dashboard():
    """로그인한 사용자의 리포지토리 목록을 보여주는 대시보드입니다."""
    if 'access_token' not in session:
        return redirect(url_for('index'))

    access_token = session.get('access_token')
    headers = {'Authorization': f'token {access_token}'}
    
    # 사용자 정보 가져오기
    user_res = requests.get(f"{GITHUB_API_URL}/user", headers=headers)
    user_info = user_res.json()
    
    # 리포지토리 목록 가져오기
    repos_res = requests.get(f"{GITHUB_API_URL}/user/repos?type=owner&sort=updated", headers=headers)
    repos = repos_res.json()
    
    return render_template('dashboard.html', user=user_info, repos=repos)

@app.route('/analyze/<owner>/<repo_name>')
def analyze_repo(owner, repo_name):
    """선택한 리포지토리의 의존성을 분석하고 결과를 보여줍니다."""
    if 'access_token' not in session:
        return redirect(url_for('index'))

    access_token = session.get('access_token')
    headers = {
        'Authorization': f'token {access_token}',
        'Accept': 'application/vnd.github+json'
    }

    # GitHub의 Dependency Graph API를 사용하여 SBOM(Software Bill of Materials)을 요청
    sbom_url = f"{GITHUB_API_URL}/repos/{owner}/{repo_name}/dependency-graph/sbom"
    sbom_res = requests.get(sbom_url, headers=headers)

    dependencies = []
    error_message = None

    if sbom_res.status_code == 200:
        sbom_data = sbom_res.json().get('sbom', {})
        packages = sbom_data.get('packages', [])

        # VVVV--- 이 부분이 수정되었습니다 ---VVVV
        for pkg in packages:
            # 패키지 이름과 버전 정보를 직접 가져옵니다.
            name = pkg.get('name', 'Unknown Package')
            version = pkg.get('versionInfo', '')

            # 이름이 존재할 경우에만 목록에 추가합니다.
            if name:
                dependencies.append(f"{name} {version}".strip())
        # ^^^^--- 여기까지 수정 ---^^^^

    else:
        error_message = f"Could not fetch dependency graph. Status: {sbom_res.status_code}. (저장소의 'Settings > Code security and analysis'에서 Dependency graph가 활성화되어 있는지 확인하세요.)"

    return render_template('results.html', repo_full_name=f"{owner}/{repo_name}", dependencies=dependencies, error=error_message)

@app.route('/logout')
def logout():
    """세션에서 access_token을 제거하여 로그아웃합니다."""
    session.pop('access_token', None)
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True, port=5000)