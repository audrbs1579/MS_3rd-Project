# web/app.py
import logging
import os
import json
from datetime import datetime, timedelta, timezone
from flask import Flask, render_template, request, redirect, session, url_for, jsonify
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from azure.cosmos import CosmosClient

app = Flask(__name__, template_folder='templates')
app.secret_key = os.urandom(24)

# -------------------------
# Config
# -------------------------
GITHUB_CLIENT_ID = os.environ.get("GITHUB_CLIENT_ID")
GITHUB_CLIENT_SECRET = os.environ.get("GITHUB_CLIENT_SECRET")
GITHUB_API_URL = "https://api.github.com"

COSMOS_CONN_STR = os.environ.get("COSMOS_DB_CONNECTION_STRING")
DB_NAME = "ProjectGuardianDB"
DEPS_CONTAINER_NAME = "Dependencies"   # pk: /userId  (role=user/repo/branch_log/checkpoint)

# -------------------------
# Cosmos DB init
# -------------------------
try:
    cosmos_client = CosmosClient.from_connection_string(COSMOS_CONN_STR)
    db = cosmos_client.get_database_client(DB_NAME)
    deps_container = db.get_container_client(DEPS_CONTAINER_NAME)  # 모든 문서(role 포함) 단일 컨테이너 사용
    logging.info("Cosmos DB connected")
except Exception as e:
    logging.exception("Cosmos init failed")
    deps_container = None

# -------------------------
# GitHub session (retry + timeout)
# -------------------------
GITHUB_TIMEOUT = (10, 45)  # (connect, read) seconds

def requests_retry_session(
    retries=3,
    backoff_factor=1.5,
    status_forcelist=(429, 500, 502, 503, 504),
    allowed_methods=frozenset(['GET', 'POST']),
):
    sess = requests.Session()
    retry = Retry(
        total=retries,
        read=retries,
        connect=retries,
        status_forcelist=status_forcelist,
        allowed_methods=allowed_methods,
        respect_retry_after_header=True,
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry, pool_connections=30, pool_maxsize=30)
    sess.mount('https://', adapter)
    sess.mount('http://', adapter)
    return sess

GH = requests_retry_session()

def gh_get(url, headers=None, params=None, timeout=GITHUB_TIMEOUT):
    return GH.get(url, headers=headers, params=params, timeout=timeout)

# -------------------------
# Helpers
# -------------------------
def _user_headers():
    if "access_token" not in session:
        return None
    return {
        "Authorization": f"token {session['access_token']}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }

def _list_all_branches(repo_full_name: str, headers: dict) -> list[dict]:
    url = f"{GITHUB_API_URL}/repos/{repo_full_name}/branches"
    branches, page = [], 1
    while True:
        r = gh_get(url, headers=headers, params={"per_page": 100, "page": page})
        if r.status_code == 404:
            return []
        r.raise_for_status()
        data = r.json() or []
        branches.extend(data)
        if len(data) < 100:
            break
        page += 1
    return branches

def _list_user_repos(headers: dict) -> list[str]:
    names = set()
    page = 1
    while True:
        r = gh_get(f"{GITHUB_API_URL}/user/repos",
                   headers=headers,
                   params={"per_page": 100, "page": page, "type": "owner", "sort": "updated"})
        if r.status_code == 401:
            break
        r.raise_for_status()
        arr = r.json() or []
        for it in arr:
            if it.get("full_name"):
                names.add(it["full_name"])
        if len(arr) < 100:
            break
        page += 1
    return sorted(names)

def _iso_day_bounds_utc(day_str: str) -> tuple[str, str]:
    # day_str: "YYYY-MM-DD" (assumed local KST date from UI)
    # Convert KST day to UTC range [since, until)
    kst = timezone(timedelta(hours=9))
    start_kst = datetime.strptime(day_str, "%Y-%m-%d").replace(tzinfo=kst)
    end_kst = start_kst + timedelta(days=1)
    start_utc = start_kst.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    end_utc = end_kst.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    return start_utc, end_utc

def _list_commits_by_day(repo_full_name: str, branch: str, day: str, headers: dict) -> list[dict]:
    since_utc, until_utc = _iso_day_bounds_utc(day)
    commits, page = [], 1
    while True:
        r = gh_get(
            f"{GITHUB_API_URL}/repos/{repo_full_name}/commits",
            headers=headers,
            params={"sha": branch, "since": since_utc, "until": until_utc, "per_page": 100, "page": page},
        )
        if r.status_code == 404:
            break
        r.raise_for_status()
        arr = r.json() or []
        for c in arr:
            commits.append({
                "sha": c.get("sha", ""),
                "message": (c.get("commit", {}) or {}).get("message", ""),
                "author": ((c.get("commit", {}) or {}).get("author", {}) or {}).get("name", ""),
                "date": ((c.get("commit", {}) or {}).get("author", {}) or {}).get("date", ""),
                "html_url": c.get("html_url", ""),
            })
        if len(arr) < 100:
            break
        page += 1
    # 최신순 정렬
    commits.sort(key=lambda x: x.get("date", ""), reverse=True)
    return commits

def _get_commit_detail(repo_full_name: str, sha: str, headers: dict) -> dict:
    r = gh_get(f"{GITHUB_API_URL}/repos/{repo_full_name}/commits/{sha}", headers=headers)
    r.raise_for_status()
    d = r.json()
    files = []
    for f in d.get("files", []) or []:
        files.append({
            "filename": f.get("filename", ""),
            "status": f.get("status", ""),
            "additions": f.get("additions", 0),
            "deletions": f.get("deletions", 0),
            # patch intentionally NOT returned
        })
    commit = (d.get("commit", {}) or {})
    author = (commit.get("author", {}) or {})
    out = {
        "sha": d.get("sha", ""),
        "author": author.get("name", "") or (d.get("author", {}) or {}).get("login", ""),
        "date": author.get("date", ""),  # UTC ISO
        "message": commit.get("message", ""),
        "stats": d.get("stats", {}),
        "files": files,
        "html_url": d.get("html_url", ""),
    }
    return out

# -------------------------
# Routes
# -------------------------
@app.route("/")
def index():
    return redirect(url_for("dashboard")) if "access_token" in session else render_template("index.html")

@app.route("/login")
def login():
    scope = "repo read:user"
    return redirect(f"https://github.com/login/oauth/authorize?client_id={GITHUB_CLIENT_ID}&scope={scope}")

@app.route("/callback")
def callback():
    code = request.args.get("code")
    token_res = requests.post(
        "https://github.com/login/oauth/access_token",
        params={"client_id": GITHUB_CLIENT_ID, "client_secret": GITHUB_CLIENT_SECRET, "code": code},
        headers={"Accept": "application/json"},
        timeout=30,
    )
    token_json = token_res.json()
    access_token = token_json.get("access_token")
    if not access_token:
        return "Access token fetch failed", 400

    session["access_token"] = access_token

    u = gh_get(f"{GITHUB_API_URL}/user", headers={"Authorization": f"token {access_token}",
                                                  "Accept": "application/vnd.github+json"})
    u.raise_for_status()
    session["user_id"] = u.json().get("login")

    # 콜백에서는 무거운 작업 금지
    return redirect(url_for("dashboard"))

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))

@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("index"))
    if not deps_container:
        return "DB connection failed", 500

    user_id = session["user_id"]

    # Dependencies 컨테이너에서 내 branch_log만 로드
    logs = list(deps_container.query_items(
        query=(
            "SELECT * FROM c "
            "WHERE c.userId = @uid AND c.role = 'branch_log' "
            "ORDER BY c.date DESC"
        ),
        parameters=[{"name": "@uid", "value": user_id}],
        enable_cross_partition_query=True
    ))

    # 레포 목록: branch_log에 있는 레포 + GH API 소유 레포
    repos_from_logs = {doc.get("repo_full_name") for doc in logs if doc.get("repo_full_name")}
    headers = _user_headers()
    repos_from_github = _list_user_repos(headers) if headers else []
    repos = sorted(set(repos_from_logs) | set(repos_from_github))

    return render_template("dashboard_branch.html", user_id=user_id, logs=logs, repos=repos)

@app.route("/sync_my_repos")
def sync_my_repos():
    # (옵션) 별도 백그라운드 동기화 트리거 지점. 현재는 대시보드로 복귀만.
    return redirect(url_for("dashboard"))

# -------- API: front-end uses these --------
@app.route("/api/branch_logs")
def api_branch_logs():
    if "user_id" not in session:
        return jsonify({"error":"unauthorized"}), 401
    if not deps_container:
        return jsonify({"error":"db not ready"}), 500

    repo = request.args.get("repo", "")
    user_id = session["user_id"]
    if not repo:
        return jsonify([])

    items = list(deps_container.query_items(
        query=(
            "SELECT * FROM c "
            "WHERE c.userId=@uid AND c.repo_full_name=@r AND c.role='branch_log' "
            "ORDER BY c.date DESC"
        ),
        parameters=[{"name":"@uid","value":user_id},{"name":"@r","value":repo}],
        enable_cross_partition_query=True
    ))
    return jsonify(items)

@app.route("/api/commits_by_day")
def api_commits_by_day():
    if "access_token" not in session:
        return jsonify({"error":"unauthorized"}), 401
    repo = request.args.get("repo", "")
    branch = request.args.get("branch", "")
    day = request.args.get("day", "")  # YYYY-MM-DD (KST 기준으로 UI 전달)
    if not (repo and branch and day):
        return jsonify({"error":"missing params"}), 400
    headers = _user_headers()
    try:
        commits = _list_commits_by_day(repo, branch, day, headers)
        return jsonify(commits)
    except requests.HTTPError as e:
        return jsonify({"error": f"github http error {e.response.status_code if e.response else ''}"}), 502
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/commit_detail")
def api_commit_detail():
    if "access_token" not in session:
        return jsonify({"error":"unauthorized"}), 401
    repo = request.args.get("repo", "")
    sha = request.args.get("sha", "")
    if not (repo and sha):
        return jsonify({"error":"missing params"}), 400
    headers = _user_headers()
    try:
        d = _get_commit_detail(repo, sha, headers)
        return jsonify(d)
    except requests.HTTPError as e:
        return jsonify({"error": f"github http error {e.response.status_code if e.response else ''}"}), 502
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=True)
