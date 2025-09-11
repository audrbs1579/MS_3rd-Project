import logging
import os
import re
import json
import requests
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, session, url_for, jsonify
from azure.cosmos import CosmosClient
from azure.cosmos.exceptions import CosmosResourceNotFoundError

# -----------------------------
# Flask
# -----------------------------
BASE_DIR = os.path.dirname(__file__)
app = Flask(
    __name__,
    template_folder=os.path.join(BASE_DIR, 'templates'),
    static_folder=os.path.join(BASE_DIR, 'static'),
)
app.secret_key = os.urandom(24)

# -----------------------------
# Config
# -----------------------------
GITHUB_CLIENT_ID = os.environ.get('GITHUB_CLIENT_ID')
GITHUB_CLIENT_SECRET = os.environ.get('GITHUB_CLIENT_SECRET')
GITHUB_API_URL = "https://api.github.com"

COSMOS_CONN_STR = os.environ.get('COSMOS_DB_CONNECTION_STRING')
DATABASE_NAME = 'ProjectGuardianDB'
DEPS_CONTAINER_NAME = 'Dependencies'  # partitionKey: /userId

# 로컬 일자 버킷을 위해 시간대 오프셋(예: KST=+9)
TZ_OFFSET_HOURS = int(os.environ.get("TZ_OFFSET_HOURS", "0"))

# -----------------------------
# Cosmos
# -----------------------------
try:
    cosmos_client = CosmosClient.from_connection_string(COSMOS_CONN_STR)
    database = cosmos_client.get_database_client(DATABASE_NAME)
    deps_container = database.get_container_client(DEPS_CONTAINER_NAME)
    logging.info("Cosmos DB 연결 성공")
except Exception as e:
    logging.critical(f"Cosmos DB 연결 실패: {e}")
    cosmos_client = database = deps_container = None

# -----------------------------
# Helpers
# -----------------------------
_ILLEGAL_ID_CHARS = re.compile(r'[\/\\\?#]')

def _safe_key(s: str) -> str:
    return _ILLEGAL_ID_CHARS.sub('_', s or '')

def _headers(access_token: str) -> dict:
    return {
        'Authorization': f'token {access_token}',
        'Accept': 'application/vnd.github.v3+json',
        'X-GitHub-Api-Version': '2022-11-28'
    }

DEP_FILE_PATTERNS = (
    "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "requirements.txt", "Pipfile", "pyproject.toml",
    "pom.xml", "build.gradle", "gradle.properties",
    "go.mod", "go.sum",
    "Cargo.toml", "Cargo.lock",
)

def _is_dep_file(filename: str) -> bool:
    fn = (filename or "").lower()
    return any(fn.endswith(p.lower()) or f"/{p.lower()}" in fn for p in DEP_FILE_PATTERNS)

def _safe_id_branch_log(user_id: str, repo_full_name: str, branch: str, day: str) -> str:
    return f"branch_log:{_safe_key(user_id)}:{_safe_key(repo_full_name)}:{_safe_key(branch)}:{day}"

def _checkpoint_id(user_id: str, repo_full_name: str, branch: str) -> str:
    return f"checkpoint:{_safe_key(user_id)}:{_safe_key(repo_full_name)}:{_safe_key(branch)}"

# -----------------------------
# GitHub API wrappers
# -----------------------------
def _list_all_branches(repo_full_name: str, headers: dict) -> list[str]:
    branches = []
    page = 1
    while True:
        url = f"{GITHUB_API_URL}/repos/{repo_full_name}/branches?per_page=100&page={page}"
        r = requests.get(url, headers=headers, timeout=15)
        if not r.ok:
            logging.warning(f"[{repo_full_name}] listBranches 실패: {r.status_code} {r.text[:200]}")
            break
        data = r.json()
        if not data:
            break
        branches.extend([b.get("name") for b in data if b.get("name")])
        page += 1
    return branches

def _list_all_commits(owner: str, repo: str, branch: str, headers: dict) -> list[dict]:
    commits, page = [], 1
    while True:
        url = f"{GITHUB_API_URL}/repos/{owner}/{repo}/commits?sha={branch}&per_page=100&page={page}"
        r = requests.get(url, headers=headers, timeout=20)
        if not r.ok:
            logging.warning(f"[{owner}/{repo}@{branch}] listCommits 실패: {r.status_code} {r.text[:200]}")
            break
        data = r.json()
        if not data:
            break
        commits.extend(data)
        page += 1
    commits.reverse()  # 오래된→최신
    return commits

def _read_checkpoint(user_id: str, repo_full_name: str, branch: str) -> str | None:
    if not deps_container:
        return None
    cp_id = _checkpoint_id(user_id, repo_full_name, branch)
    try:
        cp = deps_container.read_item(item=cp_id, partition_key=user_id)
        return cp.get("last_sha")
    except CosmosResourceNotFoundError:
        return None
    except Exception as e:
        logging.warning(f"checkpoint read 실패: {e}")
        return None

def _write_checkpoint(user_id: str, repo_full_name: str, branch: str, last_sha: str | None):
    if not deps_container:
        return
    cp_doc = {
        "id": _checkpoint_id(user_id, repo_full_name, branch),
        "role": "checkpoint",
        "userId": user_id,
        "repo_full_name": repo_full_name,
        "branch": branch,
        "last_sha": last_sha,
        "lastUpdated": datetime.utcnow().isoformat() + "Z",
    }
    deps_container.upsert_item(cp_doc)

# -----------------------------
# Backfill: repo 모든 브랜치 → 일자별 branch_log
# -----------------------------
def backfill_repo_all_branches(user_id: str, repo_full_name: str, access_token: str):
    headers = _headers(access_token)
    if '/' not in repo_full_name:
        logging.warning(f"INVALID repo: {repo_full_name}")
        return

    owner, repo = repo_full_name.split("/", 1)
    branches = _list_all_branches(repo_full_name, headers)
    if not branches:
        logging.info(f"[{repo_full_name}] 브랜치 없음")
        return

    for br in branches:
        try:
            last_sha = _read_checkpoint(user_id, repo_full_name, br)
            commits = _list_all_commits(owner, repo, br, headers)

            if last_sha:
                try:
                    idx = next(i for i,c in enumerate(commits) if c.get("sha")==last_sha)
                    commits = commits[idx+1:]  # 체크포인트 다음부터
                except StopIteration:
                    pass  # 히스토리 재작성 등 → 전체 스캔

            if not commits:
                all_commits = _list_all_commits(owner, repo, br, headers)
                latest_sha = all_commits[-1].get("sha") if all_commits else None
                _write_checkpoint(user_id, repo_full_name, br, latest_sha)
                continue

            buckets: dict[str, dict] = {}
            for c in commits:
                sha = c.get("sha")
                commit_url = c.get("url")
                try:
                    det = requests.get(commit_url, headers=headers, timeout=15)
                    det.raise_for_status()
                    files = det.json().get("files", [])
                except Exception:
                    files = []

                changed_dep_files = [f.get("filename","") for f in files if _is_dep_file(f.get("filename",""))]

                date_iso = (c.get("commit", {}).get("author", {}).get("date")
                            or c.get("commit", {}).get("committer", {}).get("date")
                            or datetime.utcnow().isoformat() + "Z")
                try:
                    dt_utc = datetime.fromisoformat(date_iso.replace('Z', '+00:00'))
                except Exception:
                    dt_utc = datetime.utcnow()
                dt_local = dt_utc + timedelta(hours=TZ_OFFSET_HOURS)
                day = dt_local.strftime('%Y-%m-%d')

                b = buckets.setdefault(day, {"commits": 0, "dep_changes": 0, "files": set(), "samples": []})
                b["commits"] += 1
                if changed_dep_files:
                    b["dep_changes"] += len(changed_dep_files)
                    for fn in changed_dep_files:
                        b["files"].add(fn)
                    if len(b["samples"]) < 3:
                        msg = (c.get("commit", {}).get("message") or "").split("\n")[0][:140]
                        b["samples"].append({
                            "sha": sha,
                            "message": msg,
                            "url": f"https://github.com/{owner}/{repo}/commit/{sha}"
                        })

            for day in sorted(buckets.keys()):
                v = buckets[day]
                doc = {
                    "id": _safe_id_branch_log(user_id, repo_full_name, br, day),
                    "role": "branch_log",
                    "userId": user_id,
                    "repo_full_name": repo_full_name,
                    "branch": br,
                    "date": day,
                    "counts": {"commits": v["commits"], "dep_changes": v["dep_changes"]},
                    "dep_files": sorted(list(v["files"])),
                    "examples": v["samples"],
                    "lastUpdated": datetime.utcnow().isoformat() + "Z",
                }
                deps_container.upsert_item(doc)

            _write_checkpoint(user_id, repo_full_name, br, commits[-1].get("sha"))

        except Exception as e:
            logging.error(f"[{repo_full_name}] backfill 실패: {e}")

# -----------------------------
# OAuth & Routes
# -----------------------------
@app.route('/')
def index():
    return redirect(url_for('dashboard')) if 'access_token' in session else render_template('index.html')

@app.route('/login')
def login():
    scope = "repo read:user"
    return redirect(f"https://github.com/login/oauth/authorize?client_id={GITHUB_CLIENT_ID}&scope={scope}")

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/callback')
def callback():
    session_code = request.args.get('code')
    token_params = {'client_id': GITHUB_CLIENT_ID, 'client_secret': GITHUB_CLIENT_SECRET, 'code': session_code}
    headers = {'Accept': 'application/json'}
    token_res = requests.post("https://github.com/login/oauth/access_token", params=token_params, headers=headers)
    token_json = token_res.json()
    access_token = token_json.get('access_token')
    if not access_token:
        return "Error: Could not retrieve access token.", 400

    session['access_token'] = access_token

    user_res = requests.get(f"{GITHUB_API_URL}/user", headers=_headers(access_token))
    user_info = user_res.json()
    user_login = user_info.get('login')
    if not user_login:
        return "Error: GitHub user not found", 400

    session['user_id'] = user_login
    sync_my_repos_to_db(user_login, access_token)
    return redirect(url_for('dashboard'))

def sync_my_repos_to_db(user_id: str, access_token: str):
    if not deps_container:
        return
    headers = _headers(access_token)

    # 내 레포 목록
    repos, page = [], 1
    while True:
        url = f"{GITHUB_API_URL}/user/repos?type=owner&per_page=100&page={page}"
        r = requests.get(url, headers=headers, timeout=20)
        if not r.ok:
            logging.error(f"list repos 실패: {r.status_code} {r.text[:200]}")
            break
        data = r.json()
        if not data:
            break
        repos.extend(data)
        page += 1

    repo_full_names = [r.get("full_name") for r in repos if r.get("full_name")]

    # role:user 업서트
    user_doc = {
        "id": f"user:{_safe_key(user_id)}",
        "role": "user",
        "userId": user_id,
        "gh_login": user_id,
        "repos": repo_full_names,
        "createdAt": datetime.utcnow().isoformat() + "Z",
        "lastUpdated": datetime.utcnow().isoformat() + "Z",
    }
    deps_container.upsert_item(user_doc)

    # 모든 레포 백필
    for full_name in repo_full_names:
        backfill_repo_all_branches(user_id, full_name, access_token)

@app.route('/sync_my_repos')
def sync_my_repos_route():
    if 'user_id' not in session or 'access_token' not in session:
        return redirect(url_for('index'))
    sync_my_repos_to_db(session['user_id'], session['access_token'])
    return redirect(url_for('dashboard'))

# -----------------------------
# Query APIs
# -----------------------------
@app.route('/api/branch_logs')
def api_branch_logs():
    if 'user_id' not in session:
        return jsonify({"error":"Unauthorized"}), 401
    user_id = session['user_id']
    repo = request.args.get("repo")
    branch = request.args.get("branch")
    since = request.args.get("since")
    until = request.args.get("until")
    if not repo:
        return jsonify({"error":"repo is required"}), 400

    where = ['c.role = "branch_log"', 'c.userId = @userId', 'c.repo_full_name = @repo']
    params = [{"name":"@userId","value":user_id}, {"name":"@repo","value":repo}]
    if branch:
        where.append("c.branch = @branch"); params.append({"name":"@branch","value":branch})
    if since and until:
        where.append("c.date BETWEEN @since AND @until")
        params.extend([{"name":"@since","value":since},{"name":"@until","value":until}])

    q = f"SELECT c.repo_full_name, c.branch, c.date, c.counts, c.dep_files, c.examples FROM c WHERE {' AND '.join(where)} ORDER BY c.date DESC"
    items = list(deps_container.query_items({"query": q, "parameters": params}, enable_cross_partition_query=True))
    return jsonify(items)

# ---- 신규: 특정 repo/branch/일자의 커밋 목록(최신순) ----
@app.route('/api/commits_by_day')
def api_commits_by_day():
    if 'access_token' not in session:
        return jsonify({"error":"Unauthorized"}), 401
    access_token = session['access_token']

    repo = request.args.get('repo')          # owner/repo
    branch = request.args.get('branch')      # branch name
    day = request.args.get('day')            # YYYY-MM-DD (local tz)

    if not repo or not branch or not day:
        return jsonify({"error":"repo, branch, day are required"}), 400

    try:
        # local day → UTC since/until
        start_local = datetime.fromisoformat(day)  # 00:00 local
        end_local = start_local + timedelta(days=1) - timedelta(seconds=1)
        start_utc = start_local - timedelta(hours=TZ_OFFSET_HOURS)
        end_utc = end_local - timedelta(hours=TZ_OFFSET_HOURS)

        params = {
            "sha": branch,
            "since": start_utc.isoformat(timespec='seconds') + "Z",
            "until": end_utc.isoformat(timespec='seconds') + "Z",
            "per_page": 100
        }

        # 페이징
        commits = []
        page = 1
        headers = _headers(access_token)
        while True:
            url = f"{GITHUB_API_URL}/repos/{repo}/commits"
            p = params | {"page": page}
            r = requests.get(url, headers=headers, params=p, timeout=20)
            if not r.ok:
                return jsonify({"error": f"GitHub {r.status_code}", "detail": r.text[:300]}), r.status_code
            arr = r.json()
            if not arr:
                break
            commits.extend(arr)
            if len(arr) < 100:
                break
            page += 1

        # 최신순으로 정렬
        commits.sort(key=lambda c: (c.get("commit", {}).get("author", {}).get("date") or ""), reverse=True)

        out = []
        for c in commits:
            sha = c.get("sha")
            msg = (c.get("commit", {}).get("message") or "").split("\n")[0]
            author_name = c.get("commit", {}).get("author", {}).get("name")
            author_login = (c.get("author") or {}).get("login")
            date_iso = c.get("commit", {}).get("author", {}).get("date")
            html_url = f"https://github.com/{repo}/commit/{sha}"
            out.append({
                "sha": sha,
                "message": msg,
                "author_name": author_name,
                "author_login": author_login,
                "date": date_iso,
                "url": html_url
            })
        return jsonify(out)
    except Exception as e:
        logging.exception("api_commits_by_day failed")
        return jsonify({"error": str(e)}), 500

# ---- 신규: 커밋 상세 ----
@app.route('/api/commit_detail')
def api_commit_detail():
    if 'access_token' not in session:
        return jsonify({"error":"Unauthorized"}), 401
    access_token = session['access_token']

    repo = request.args.get('repo')  # owner/repo
    sha = request.args.get('sha')
    if not repo or not sha:
        return jsonify({"error":"repo and sha are required"}), 400

    headers = _headers(access_token)
    url = f"{GITHUB_API_URL}/repos/{repo}/commits/{sha}"
    r = requests.get(url, headers=headers, timeout=20)
    if not r.ok:
        return jsonify({"error": f"GitHub {r.status_code}", "detail": r.text[:300]}), r.status_code

    j = r.json()
    stats = j.get("stats", {})  # additions, deletions, total
    files = j.get("files", [])  # filename, status, additions, deletions, changes, patch
    out_files = []
    for f in files:
        out_files.append({
            "filename": f.get("filename"),
            "status": f.get("status"),
            "additions": f.get("additions"),
            "deletions": f.get("deletions"),
            "changes": f.get("changes"),
            "patch": (f.get("patch") or "")[:1000]  # 너무 길면 커팅
        })
    return jsonify({
        "sha": sha,
        "message": j.get("commit", {}).get("message"),
        "author": (j.get("author") or {}).get("login") or j.get("commit", {}).get("author", {}).get("name"),
        "date": j.get("commit", {}).get("author", {}).get("date"),
        "html_url": j.get("html_url"),
        "stats": stats,
        "files": out_files
    })

# -----------------------------
# Dashboard
# -----------------------------
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('index'))
    if not deps_container:
        return "Error: DB 연결 실패", 500

    user_id = session['user_id']

    q_logs = """
    SELECT c.repo_full_name, c.branch, c.date, c.counts, c.dep_files, c.examples
    FROM c
    WHERE c.role = "branch_log" AND c.userId = @userId
    ORDER BY c.date DESC
    """
    params = [{"name":"@userId","value":user_id}]
    logs = list(deps_container.query_items({"query": q_logs, "parameters": params}, enable_cross_partition_query=True))

    q_user = """
    SELECT TOP 1 c.repos
    FROM c
    WHERE c.role = "user" AND c.userId = @userId
    """
    user_doc = list(deps_container.query_items({"query": q_user, "parameters": params}, enable_cross_partition_query=True))
    repos = user_doc[0].get("repos", []) if user_doc else []

    return render_template('dashboard_branch.html', user_id=user_id, logs=logs, repos=repos)

# -----------------------------
# Run
# -----------------------------
if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=True)
