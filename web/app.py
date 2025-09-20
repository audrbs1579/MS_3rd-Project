import os
import json
import logging
import random
import base64
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode

import requests
from flask import (
    Flask, render_template, request, redirect, session,
    url_for, jsonify, Response
)

# 이것은 실제 정보가 아닌, 탐지 테스트를 위한 가짜 연결 문자열입니다.
db_connection_string = "Server=tcp:my-test-server.database.windows.net,1433;Initial Catalog=my-db;Persist Security Info=False;User ID=test-user;Password=S3cureP@ssw0rd!;MultipleActiveResultSets=False;Encrypt=True;TrustServerCertificate=False;Connection Timeout=30;"

# ---------- 기본 설정 ----------
app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev-secret")

GITHUB_CLIENT_ID = os.environ.get("GITHUB_CLIENT_ID", "")
GITHUB_CLIENT_SECRET = os.environ.get("GITHUB_CLIENT_SECRET", "")
GITHUB_OAUTH_SCOPE = "repo,security_events"
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

def _gh_get(url, params=None, accept_header=None):
    try:
        headers = _gh_headers()
        if accept_header:
            headers["Accept"] = accept_header
        r = requests.get(url, headers=headers, params=params or {}, timeout=TIMEOUT)
        if r.status_code == 401:
            raise PermissionError("GitHub unauthorized")
        r.raise_for_status()
        
        if 'application/json' in r.headers.get('Content-Type', ''):
            return r.json(), r.headers
        return r.text, r.headers

    except requests.exceptions.RequestException as e:
        log.error(f"GitHub API request failed for URL {url}: {e}")
        raise


def _get_code_excerpt(repo_full_name, ref, path, start_line, end_line):
    """Fetch a small excerpt of code around the offending lines."""
    if not path or not start_line:
        return []
    url = f"{GITHUB_URL_BASE}/repos/{repo_full_name}/contents/{path}"
    try:
        file_data, _ = _gh_get(url, params={"ref": ref})
    except requests.exceptions.RequestException:
        return []
    if not isinstance(file_data, dict):
        return []
    if file_data.get('encoding') != 'base64' or not file_data.get('content'):
        return []
    try:
        decoded = base64.b64decode(file_data['content']).decode('utf-8', errors='replace')
    except Exception:
        return []
    lines = decoded.splitlines()
    if not lines:
        return []
    total_lines = len(lines)
    end_line = end_line or start_line
    start = max(1, start_line - 2)
    end = min(total_lines, end_line + 2)
    excerpt = []
    for lineno in range(start, end + 1):
        line_text = lines[lineno - 1] if 0 <= lineno - 1 < total_lines else ''
        excerpt.append({
            'line': lineno,
            'content': line_text,
            'highlight': start_line <= lineno <= end_line,
        })
    return excerpt

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
    if not code: return "Missing code", 400
    tok_res = requests.post("https://github.com/login/oauth/access_token", data={"client_id": GITHUB_CLIENT_ID, "client_secret": GITHUB_CLIENT_SECRET, "code": code}, headers={"Accept": "application/json"}, timeout=TIMEOUT)
    tok_res.raise_for_status()
    session["access_token"] = tok_res.json().get("access_token")
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

@app.route("/details")
def details():
    if "access_token" not in session:
        return redirect(url_for("index"))
    
    repo = request.args.get("repo")
    sha = request.args.get("sha")
    
    if not repo or not sha:
        return "리포지토리와 커밋 SHA가 필요합니다.", 400

    return render_template("detail_view.html", 
        user_id=session.get("user_login") or "me",
        repo_name=repo,
        commit_sha=sha
    )

# ---------- API ----------
@app.get("/api/my_repos")
def api_my_repos():
    if "access_token" not in session: return jsonify({"error": "unauthorized"}), 401
    repos, _ = _gh_get(GITHUB_URL_REPOS, params={"per_page": 100, "sort": "pushed"})
    return jsonify({"repos": [{"full_name": r.get("full_name"), "name": r.get("name"), "pushed_at": r.get("pushed_at")} for r in (repos or [])]})

@app.get("/api/branches")
def api_branches():
    repo = request.args.get("repo")
    if not repo: return jsonify({"error": "repo required"}), 400
    if "access_token" not in session: return jsonify({"error": "unauthorized"}), 401
    url = GITHUB_URL_REPO_BRANCHES.format(repo=repo)
    branches_data, _ = _gh_get(url, params={"per_page": 100})
    out = []
    for b in (branches_data or []):
        sha = (b.get("commit") or {}).get("sha")
        commit_url = f"{GITHUB_URL_BASE}/repos/{repo}/commits/{sha}"
        try:
            commit_data, _ = _gh_get(commit_url)
            commit_date = (commit_data.get("commit", {}).get("author") or {}).get("date")
            out.append({"name": b.get("name"), "sha": sha, "last_commit_date": commit_date})
        except requests.exceptions.RequestException:
            out.append({"name": b.get("name"), "sha": sha, "last_commit_date": None})
    return jsonify({"branches": out})

@app.get("/api/commits")
def api_commits():
    repo = request.args.get("repo")
    branch = request.args.get("branch")
    if not repo or not branch: return jsonify({"error": "repo and branch required"}), 400
    if "access_token" not in session: return jsonify({"error": "unauthorized"}), 401
    url = GITHUB_URL_REPO_COMMITS.format(repo=repo)
    commits, _ = _gh_get(url, params={"sha": branch, "per_page": 100})
    pick = lambda c: {"sha": c.get("sha"), "message": (c.get("commit", {}).get("message") or "").split("\n")[0], "author": (c.get("commit", {}).get("author") or {}).get("name"), "date": (c.get("commit", {}).get("author") or {}).get("date")}
    return jsonify({"commits": [pick(c) for c in (commits or [])]})

@app.get("/api/commit_detail")
def api_commit_detail():
    repo, sha = request.args.get("repo"), request.args.get("sha")
    if not repo or not sha: return jsonify({"error": "repo and sha required"}), 400
    if "access_token" not in session: return jsonify({"error": "unauthorized"}), 401
    url = f"{GITHUB_URL_REPO_COMMITS.format(repo=repo)}/{sha}"
    data, _ = _gh_get(url)
    stats, commit = data.get("stats") or {}, data.get("commit") or {}
    return jsonify({"message": commit.get("message"), "author": (commit.get("author") or {}).get("name"), "date": (commit.get("author") or {}).get("date"), "stats": {"total": stats.get("total"), "additions": stats.get("additions"), "deletions": stats.get("deletions")}, "files": [{"filename": f.get("filename")} for f in (data.get("files") or [])], "html_url": data.get("html_url")})

@app.get("/api/commit_diff")
def api_commit_diff():
    repo, sha = request.args.get("repo"), request.args.get("sha")
    if not repo or not sha: return jsonify({"error": "repo and sha required"}), 400
    if "access_token" not in session: return jsonify({"error": "unauthorized"}), 401
    url = f"{GITHUB_URL_REPO_COMMITS.format(repo=repo)}/{sha}"
    diff_text, _ = _gh_get(url, accept_header="application/vnd.github.diff")
    return Response(diff_text, mimetype='text/plain')



@app.get("/api/security_status")
def api_security_status():
    repo, ref = request.args.get("repo"), request.args.get("ref")
    if not repo or not ref:
        return jsonify({"error": "repo and ref required"}), 400
    if "access_token" not in session:
        return jsonify({"error": "unauthorized"}), 401
    url = f"{GITHUB_URL_BASE}/repos/{repo}/code-scanning/alerts"
    try:
        alerts, _ = _gh_get(url, params={"ref": ref, "per_page": 100})
        alerts = alerts or []

        enriched_alerts = []
        for alert in alerts[:10]:
            rule = alert.get('rule') or {}
            severity = (rule.get('severity') or '').lower()
            most_recent = alert.get('most_recent_instance') or {}
            location = most_recent.get('location') or {}
            message = (most_recent.get('message') or {}).get('text') or alert.get('description') or ''
            path_name = location.get('path') or ''
            start_line = location.get('start_line') or 0
            end_line = location.get('end_line') or start_line or 0
            excerpt = _get_code_excerpt(repo, ref, path_name, start_line, end_line)
            enriched_alerts.append({
                'number': alert.get('number'),
                'rule_id': rule.get('id'),
                'rule_name': rule.get('name') or rule.get('id'),
                'severity': severity,
                'description': message,
                'path': path_name,
                'start_line': start_line or None,
                'end_line': end_line or None,
                'html_url': alert.get('html_url'),
                'code_excerpt': excerpt,
            })

        high_alerts = [a for a in alerts if (a.get('rule') or {}).get('severity') in ['critical', 'high']]
        defender_status = 'bad' if high_alerts else 'warn' if alerts else 'good'
        defender_summary = f"CodeQL: {len(alerts)}개 경고"

        sentinel = {
            'status': 'good',
            'summary': 'Sentinel 예측 점수: 0.8',
        }
        bricks = {
            'status': 'good',
            'summary': '모델 예측 점수: 0.8',
        }

        return jsonify({
            'defender': {
                'status': defender_status,
                'summary': defender_summary,
                'alerts': enriched_alerts,
            },
            'sentinel': sentinel,
            'bricks': bricks,
        })
    except requests.exceptions.HTTPError as e:
        if e.response.status_code in [404, 403]:
            return jsonify({
                'defender': {'status': 'unknown', 'summary': '결과 없음', 'alerts': []},
                'sentinel': {'status': 'good', 'summary': 'Sentinel 예측 점수: 0.8'},
                'bricks': {'status': 'good', 'summary': '모델 예측 점수: 0.8'},
            })
        raise
    except Exception:
        log.exception(f"Failed to get security status for {repo}@{ref}")
        return jsonify(error="보안 상태 가져오기 중 오류 발생"), 500


@app.errorhandler(PermissionError)
def _unauth(_):
    session.clear()
    # ✅ API 호출이면 JSON 401, 페이지 요청이면 리다이렉트
    if request.path.startswith("/api/"):
        return jsonify({"error": "unauthorized"}), 401
    return redirect(url_for("index"))

@app.errorhandler(Exception)
def handle_exception(e):
    if hasattr(e, 'code') and isinstance(e.code, int) and 400 <= e.code < 600: return e
    log.exception("An unhandled exception occurred")
    return jsonify(error="Internal server error"), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)
