import os
import json
import logging
from datetime import datetime, timezone, timedelta
from collections import defaultdict

import requests
from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from azure.cosmos import CosmosClient, PartitionKey, exceptions as cxe

# -------------------------
# Flask
# -------------------------
app = Flask(__name__, template_folder='templates')
app.secret_key = os.environ.get("FLASK_SECRET", os.urandom(32))

# -------------------------
# Config
# -------------------------
GITHUB_CLIENT_ID = os.environ.get('GITHUB_CLIENT_ID', '')
GITHUB_CLIENT_SECRET = os.environ.get('GITHUB_CLIENT_SECRET', '')
GITHUB_API = "https://api.github.com"

COSMOS_CONN = os.environ.get('COSMOS_DB_CONNECTION_STRING', '')
DB_NAME = "ProjectGuardianDB"
LOGS_CONTAINER = "BranchLogs"        # 파티션키 /user_id
DEPS_CONTAINER = "Dependencies"      # 기존 저장소(참고용), 파티션키 /userId

# -------------------------
# Cosmos helpers
# -------------------------
def _cosmos():
    if not COSMOS_CONN:
        raise RuntimeError("COSMOS_DB_CONNECTION_STRING is not set")
    cli = CosmosClient.from_connection_string(COSMOS_CONN)
    db = cli.create_database_if_not_exists(id=DB_NAME)
    # BranchLogs
    logs = db.create_container_if_not_exists(
        id=LOGS_CONTAINER,
        partition_key=PartitionKey(path="/user_id"),
        offer_throughput=400,
    )
    # Dependencies(기존)
    db.create_container_if_not_exists(
        id=DEPS_CONTAINER,
        partition_key=PartitionKey(path="/userId"),
        offer_throughput=400,
    )
    return cli, db, logs

def _headers(token: str):
    return {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github+json",
        "User-Agent": "ProjectGuardian"
    }

# -------------------------
# GitHub helpers
# -------------------------
def list_user_repos(token: str):
    headers = _headers(token)
    repos = []
    page = 1
    while True:
        r = requests.get(f"{GITHUB_API}/user/repos?type=owner&per_page=100&page={page}", headers=headers, timeout=20)
        if not r.ok:
            break
        batch = r.json()
        if not batch:
            break
        repos.extend([x.get("full_name") for x in batch if x.get("full_name")])
        page += 1
    return repos

def list_branches(repo_full: str, token: str):
    headers = _headers(token)
    out = []
    page = 1
    while True:
        r = requests.get(f"{GITHUB_API}/repos/{repo_full}/branches?per_page=100&page={page}", headers=headers, timeout=20)
        if not r.ok:
            break
        arr = r.json()
        if not arr:
            break
        out.extend([b["name"] for b in arr if "name" in b])
        page += 1
    return out

def list_commits(repo_full: str, branch: str, token: str, since_iso: str | None = None):
    headers = _headers(token)
    params = {"sha": branch, "per_page": 100}
    if since_iso:
        params["since"] = since_iso
    page = 1
    commits = []
    while True:
        r = requests.get(f"{GITHUB_API}/repos/{repo_full}/commits", headers=headers, params={**params, "page": page}, timeout=25)
        if not r.ok:
            break
        arr = r.json()
        if not isinstance(arr, list) or not arr:
            break
        commits.extend(arr)
        page += 1
        if page > 10:  # 안전 가드(최대 1000건)
            break
    return commits

def get_commit(repo_full: str, sha: str, token: str):
    headers = _headers(token)
    r = requests.get(f"{GITHUB_API}/repos/{repo_full}/commits/{sha}", headers=headers, timeout=20)
    if r.ok:
        return r.json()
    return {"error": f"github status {r.status_code}"}

# -------------------------
# Backfill to BranchLogs
# -------------------------
def upsert_branch_logs(user_id: str, repo_full: str, branch: str, commits: list, logs_container):
    """
    commits: GitHub /commits 응답 배열
    BranchLogs 문서 스키마:
      { id, user_id, repo_full_name, branch, date, counts:{commits, dep_files}, examples:[{sha,message,commit_time}], last_sha }
    """
    # 커밋을 날짜별(KST 기준은 프런트에서 표시, 저장은 UTC ISO)로 그룹
    by_day = defaultdict(list)
    for c in commits:
        sha = c.get("sha")
        msg = (c.get("commit", {}).get("message") or "").split("\n")[0]
        dt_iso = c.get("commit", {}).get("committer", {}).get("date") or c.get("commit", {}).get("author", {}).get("date")
        if not dt_iso:
            continue
        day = dt_iso[:10]  # YYYY-MM-DD (UTC)
        by_day[day].append({"sha": sha, "message": msg, "commit_time": dt_iso})

    for day, arr in by_day.items():
        doc_id = f"{user_id}::{repo_full}::{branch}::{day}"
        dep_cnt = 0  # 여기서는 파일 diff를 안보니 0; 필요시 commit detail로 증분 카운트 가능
        body = {
            "id": doc_id,
            "user_id": user_id,
            "repo_full_name": repo_full,
            "branch": branch,
            "date": day,
            "counts": {"commits": len(arr), "dep_files": dep_cnt},
            "examples": sorted(arr, key=lambda x: x["commit_time"], reverse=True)[:50],
            "last_sha": arr[0]["sha"] if arr else None,
        }
        logs_container.upsert_item(body)

def backfill_repo(user_id: str, repo_full: str, token: str):
    _, _, logs_container = _cosmos()
    branches = list_branches(repo_full, token)
    for br in branches or []:
        commits = list_commits(repo_full, br, token)
        if commits:
            upsert_branch_logs(user_id, repo_full, br, commits, logs_container)

# -------------------------
# Flask routes
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
    if not code:
        return "no code", 400
    r = requests.post(
        "https://github.com/login/oauth/access_token",
        headers={"Accept": "application/json"},
        data={"client_id": GITHUB_CLIENT_ID, "client_secret": GITHUB_CLIENT_SECRET, "code": code},
        timeout=20,
    )
    tok = r.json().get("access_token")
    if not tok:
        return "token error", 400
    session["access_token"] = tok

    ur = requests.get(f"{GITHUB_API}/user", headers=_headers(tok), timeout=20)
    user_login = ur.json().get("login")
    if not user_login:
        return "user error", 400
    session["user_id"] = user_login

    # 최초 로그인 시 간단 백필(시간많이 안쓰게 최근 repo만)
    try:
        repos = list_user_repos(tok)[:8]
        for rf in repos:
            backfill_repo(user_login, rf, tok)
    except Exception:
        logging.exception("initial backfill failed")

    return redirect(url_for("dashboard"))

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))

@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("index"))
    user_id = session["user_id"]

    try:
        _, _, logs_container = _cosmos()
        it = logs_container.query_items(
            "SELECT * FROM c WHERE c.user_id = @uid ORDER BY c.date DESC",
            parameters=[{"name": "@uid", "value": user_id}],
            enable_cross_partition_query=True,
        )
        docs = list(it)
    except Exception:
        logging.exception("query BranchLogs failed")
        docs = []

    # 화면 좌측 repo chip 목록
    repo_set = []
    seen = set()
    for d in docs:
        rf = d.get("repo_full_name")
        if rf and rf not in seen:
            seen.add(rf)
            repo_set.append(rf)

    return render_template("dashboard_branch.html", user_id=user_id, logs=docs, repos=repo_set)

# ------- REST used by front -------
@app.get("/api/branch_logs")
def api_branch_logs():
    uid = request.args.get("userId")
    repo = request.args.get("repo")
    if not uid:
        return jsonify([])
    try:
        _, _, logs_container = _cosmos()
        if repo:
            q = "SELECT * FROM c WHERE c.user_id=@u AND c.repo_full_name=@r ORDER BY c.date DESC"
            params = [{"name":"@u","value":uid},{"name":"@r","value":repo}]
        else:
            q = "SELECT * FROM c WHERE c.user_id=@u ORDER BY c.date DESC"
            params = [{"name":"@u","value":uid}]
        it = logs_container.query_items(q, parameters=params, enable_cross_partition_query=True)
        return jsonify(list(it))
    except cxe.CosmosResourceNotFoundError:
        return jsonify([])
    except Exception:
        logging.exception("api_branch_logs error")
        return jsonify([])

@app.get("/api/commit_detail")
def api_commit_detail():
    if "access_token" not in session:
        return jsonify({"error":"unauthorized"}), 401
    repo = request.args.get("repo")
    sha = request.args.get("sha")
    if not repo or not sha:
        return jsonify({"error":"missing"}), 400
    data = get_commit(repo, sha, session["access_token"])
    return jsonify(data)

@app.route("/sync_my_repos")
def sync_my_repos():
    if "user_id" not in session or "access_token" not in session:
        return redirect(url_for("index"))
    user_id = session["user_id"]
    token = session["access_token"]
    try:
        repos = list_user_repos(token)
        for rf in repos:
            backfill_repo(user_id, rf, token)
    except Exception:
        logging.exception("sync_my_repos failed")
    return redirect(url_for("dashboard"))

# -------------------------
# Main
# -------------------------
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
