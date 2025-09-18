import os
import json
import logging
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode

import requests
from flask import (
    Flask, render_template, request, redirect, session,
    url_for, jsonify
)

# ---------- 기본 설정 ----------
app =Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev-secret")

GITHUB_CLIENT_ID = os.environ.get("GITHUB_CLIENT_ID", "")
GITHUB_CLIENT_SECRET = os.environ.get("GITHUB_CLIENT_SECRET", "")
GITHUB_OAUTH_SCOPE = "repo"
TIMEOUT = 15

# GitHub API URL
GITHUB_URL_BASE = "https://api.github.com"
GITHUB_URL_USER = f"{GITHUB_URL_BASE}/user"
GITHUB_URL_REPOS = f"{GITHUB_URL_BASE}/user/repos"
GITHUB_URL_REPO_COMMITS = f"{GITHUB_URL_BASE}/repos/{{repo}}/commits"
GITHUB_URL_REPO_BRANCHES = f"{GITHUB_URL_BASE}/repos/{{repo}}/branches"

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("web.app")

# ---------- 유틸 ----------
def _gh_headers():
    tok = session.get("access_token")
    h = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "branch-activity-dashboard",
    }
    if tok:
        h["Authorization"] = f"Bearer {tok}"
    return h

def _gh_get(url, params=None):
    """GitHub GET with 기본 타임아웃/에러 처리."""
    try:
        r = requests.get(url, headers=_gh_headers(), params=params or {}, timeout=TIMEOUT)
        if r.status_code == 401:
            raise PermissionError("GitHub unauthorized")
        r.raise_for_status()
        return r.json(), r.headers
    except requests.exceptions.RequestException as e:
        log.error(f"GitHub API request failed for URL {url}: {e}")
        raise

def _page_all(url, params=None, max_pages=10):
    """Link 헤더 따라 최대 max_pages 페이지 수집."""
    out = []
    next_url = url
    next_params = params or {}
    for _ in range(max_pages):
        try:
            data, headers = _gh_get(next_url, next_params)
            if isinstance(data, list):
                out.extend(data)
            else:
                out.append(data)

            link = headers.get("Link", "")
            nxt = None
            if link:
                parts = link.split(",")
                for p in parts:
                    if 'rel="next"' in p:
                        s = p.split(";")[0].strip()
                        if s.startswith("<") and s.endswith(">"):
                            nxt = s[1:-1]
            if not nxt:
                break
            next_url, next_params = nxt, None
        except requests.exceptions.RequestException:
            log.warning(f"Failed to fetch next page for {url}. Returning partial data.")
            break
    return out

# ---------- 라우팅 ----------
@app.route("/")
def index():
    if "access_token" not in session:
        return render_template("index.html")
    return redirect(url_for("dashboard"))

@app.route("/login")
def login():
    params = {
        "client_id": GITHUB_CLIENT_ID,
        "scope": GITHUB_OAUTH_SCOPE,
        "allow_signup": "true",
    }
    return redirect(f"https://github.com/login/oauth/authorize?{urlencode(params)}")

@app.route("/callback")
def callback():
    code = request.args.get("code")
    if not code:
        return "Missing code", 400

    tok_res = requests.post(
        "https://github.com/login/oauth/access_token",
        data={
            "client_id": GITHUB_CLIENT_ID,
            "client_secret": GITHUB_CLIENT_SECRET,
            "code": code,
        },
        headers={"Accept": "application/json"},
        timeout=TIMEOUT,
    )
    tok_res.raise_for_status()
    payload = tok_res.json()
    session["access_token"] = payload.get("access_token")

    me, _ = _gh_get(GITHUB_URL_USER)
    session["user_login"] = me.get("login", "")

    return redirect(url_for("dashboard"))

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))

@app.route("/dashboard")
def dashboard():
    if "access_token" not in session:
        return redirect(url_for("index"))
    return render_template("dashboard_branch.html", user_id=session.get("user_login") or "me")

# ---------- API ----------
@app.get("/api/my_repos")
def api_my_repos():
    if "access_token" not in session:
        return jsonify({"error": "unauthorized"}), 401
    params = {"per_page": 100, "sort": "pushed"}
    repos = _page_all(GITHUB_URL_REPOS, params=params, max_pages=5)
    trimmed = [
        {
            "full_name": r.get("full_name"),
            "name": r.get("name"),
            "private": r.get("private"),
            "pushed_at": r.get("pushed_at"),
        } for r in repos
    ]
    return jsonify({"repos": trimmed})

# --- 수정된 부분: 브랜치의 마지막 커밋 시간 정보 추가 ---
@app.get("/api/branches")
def api_branches():
    repo = request.args.get("repo")
    if not repo: return jsonify({"error": "repo required"}), 400
    if "access_token" not in session: return jsonify({"error": "unauthorized"}), 401

    url = GITHUB_URL_REPO_BRANCHES.format(repo=repo)
    branches_data = _page_all(url, params={"per_page": 100}, max_pages=3)
    
    out = []
    for b in branches_data:
        sha = (b.get("commit") or {}).get("sha")
        # 각 브랜치의 최신 커밋 정보를 가져와서 날짜를 포함시킴
        commit_url = f"{GITHUB_URL_BASE}/repos/{repo}/commits/{sha}"
        try:
            commit_data, _ = _gh_get(commit_url)
            commit_date = (commit_data.get("commit", {}).get("author") or {}).get("date")
            out.append({"name": b.get("name"), "sha": sha, "last_commit_date": commit_date})
        except requests.exceptions.RequestException:
            # 커밋 정보를 가져오지 못하면 날짜 없이 추가
            out.append({"name": b.get("name"), "sha": sha, "last_commit_date": None})

    return jsonify({"branches": out})
# --- 수정 끝 ---

@app.get("/api/commits")
def api_commits():
    repo = request.args.get("repo")
    branch = request.args.get("branch")
    if not repo or not branch: return jsonify({"error": "repo and branch required"}), 400
    if "access_token" not in session: return jsonify({"error": "unauthorized"}), 401

    params = {"sha": branch, "per_page": 100}
    if request.args.get("since"): params["since"] = request.args.get("since")
    if request.args.get("until"): params["until"] = request.args.get("until")

    url = GITHUB_URL_REPO_COMMITS.format(repo=repo)
    commits = _page_all(url, params=params, max_pages=5)

    def pick(c):
        commit, author = (c.get("commit") or {}), (c.get("commit", {}).get("author") or {})
        return {
            "sha": c.get("sha"),
            "message": (commit.get("message") or "").split("\n")[0],
            "author": (author.get("name") or ""),
            "date": author.get("date"),
            "html_url": c.get("html_url"),
        }
    return jsonify({"commits": [pick(c) for c in commits]})

@app.get("/api/commit_detail")
def api_commit_detail():
    repo = request.args.get("repo")
    sha = request.args.get("sha")
    if not repo or not sha: return jsonify({"error": "repo and sha required"}), 400
    if "access_token" not in session: return jsonify({"error": "unauthorized"}), 401

    url = f"{GITHUB_URL_REPO_COMMITS.format(repo=repo)}/{sha}"
    data, _ = _gh_get(url)
    files, stats, commit = data.get("files") or [], data.get("stats") or {}, data.get("commit") or {}
    author = (data.get("commit", {}).get("author") or {})
    return jsonify({
        "sha": data.get("sha"),
        "message": (commit.get("message") or ""),
        "author": author.get("name"),
        "date": author.get("date"),
        "stats": {
            "total": stats.get("total"),
            "additions": stats.get("additions"),
            "deletions": stats.get("deletions"),
        },
        "files": [
            {
                "filename": f.get("filename"),
                "status": f.get("status"),
                "additions": f.get("additions"),
                "deletions": f.get("deletions"),
                "changes": f.get("changes"),
                "raw_url": f.get("raw_url"),
                "blob_url": f.get("blob_url"),
            } for f in files
        ],
        "html_url": data.get("html_url"),
    })

# ---------- 오류 처리 ----------
@app.errorhandler(PermissionError)
def _unauth(_):
    session.clear()
    return redirect(url_for("index"))

@app.errorhandler(Exception)
def handle_exception(e):
    if hasattr(e, 'code') and isinstance(e.code, int) and 400 <= e.code < 600:
        return e
    log.exception("An unhandled exception occurred")
    return jsonify(error="Internal server error"), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)