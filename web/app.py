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
app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev-secret")

GITHUB_CLIENT_ID = os.environ.get("GITHUB_CLIENT_ID", "")
GITHUB_CLIENT_SECRET = os.environ.get("GITHUB_CLIENT_SECRET", "")
GITHUB_OAUTH_SCOPE = "repo"  # private repo 필요 없으면 'read:user repo:status' 등으로 조정
GITHUB_API = "https://api.github.com"

TIMEOUT = 15  # GitHub API 타임아웃(초)

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
    r = requests.get(url, headers=_gh_headers(), params=params or {}, timeout=TIMEOUT)
    if r.status_code == 401:
        # 토큰 만료/권한 문제 → 로그인 다시
        raise PermissionError("GitHub unauthorized")
    r.raise_for_status()
    return r.json(), r.headers


def _page_all(url, params=None, max_pages=10):
    """Link 헤더 따라 최대 max_pages 페이지 수집."""
    out = []
    next_url = url
    next_params = params or {}
    for _ in range(max_pages):
        data, headers = _gh_get(next_url, next_params)
        if isinstance(data, list):
            out.extend(data)
        else:
            out.append(data)

        link = headers.get("Link", "")
        # 다음 링크 파싱
        nxt = None
        if link:
            parts = link.split(",")
            for p in parts:
                if 'rel="next"' in p:
                    # <url>; rel="next"
                    s = p.split(";")[0].strip()
                    if s.startswith("<") and s.endswith(">"):
                        nxt = s[1:-1]
        if not nxt:
            break
        next_url, next_params = nxt, None  # 다음은 URL 자체에 쿼리 포함됨
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

    # 액세스 토큰 교환
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

    # 사용자 정보
    me, _ = _gh_get(f"{GITHUB_API}/user")
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

    return render_template(
        "dashboard_branch.html",
        user_id=session.get("user_login") or "me"
    )

# ---------- API: 모두 '누를 때만' 조회 ----------
@app.get("/api/my_repos")
def api_my_repos():
    """내 리포지토리 목록 (owner/repo → repo명만 출력은 프런트에서 처리)."""
    if "access_token" not in session:
        return jsonify({"error": "unauthorized"}), 401

    # 본인 소유/콜라보 포함. 필요 시 visibility, affiliation 등 파라미터 조정
    params = {
        "per_page": 100,
        "sort": "pushed",
    }
    repos = _page_all(f"{GITHUB_API}/user/repos", params=params, max_pages=5)
    # 필요한 필드만 축소
    trimmed = [
        {
            "full_name": r.get("full_name"),
            "name": r.get("name"),
            "private": r.get("private"),
            "pushed_at": r.get("pushed_at"),
        }
        for r in repos
    ]
    return jsonify({"repos": trimmed})

@app.get("/api/branches")
def api_branches():
    """특정 repo 의 브랜치 목록."""
    repo = request.args.get("repo")
    if not repo:
        return jsonify({"error": "repo required"}), 400

    branches = _page_all(f"{GITHUB_API}/repos/{repo}/branches", params={"per_page": 100}, max_pages=3)
    out = [{"name": b.get("name"), "sha": (b.get("commit") or {}).get("sha")} for b in branches]
    return jsonify({"branches": out})

@app.get("/api/commits")
def api_commits():
    """특정 repo + branch 의 커밋 목록. since/until 옵션 지원.
       반환은 최신순(기본 GitHub). 프런트가 날짜별로 그룹핑."""
    repo = request.args.get("repo")
    branch = request.args.get("branch")
    since = request.args.get("since")  # ISO8601
    until = request.args.get("until")  # ISO8601
    if not repo or not branch:
        return jsonify({"error": "repo and branch required"}), 400

    params = {"sha": branch, "per_page": 100}
    if since:
        params["since"] = since
    if until:
        params["until"] = until

    commits = _page_all(f"{GITHUB_API}/repos/{repo}/commits", params=params, max_pages=5)

    # 필요한 필드만 축소
    def pick(c):
        commit = c.get("commit") or {}
        author = commit.get("author") or {}
        return {
            "sha": c.get("sha"),
            "message": (commit.get("message") or "").split("\n")[0],
            "author": (author.get("name") or ""),
            "date": author.get("date"),
            "html_url": c.get("html_url"),
        }

    out = [pick(c) for c in commits]
    return jsonify({"commits": out})

@app.get("/api/commit_detail")
def api_commit_detail():
    """특정 커밋 상세 (files 변경 요약만)."""
    repo = request.args.get("repo")
    sha = request.args.get("sha")
    if not repo or not sha:
        return jsonify({"error": "repo and sha required"}), 400

    data, _ = _gh_get(f"{GITHUB_API}/repos/{repo}/commits/{sha}")
    files = data.get("files") or []
    stats = data.get("stats") or {}
    commit = data.get("commit") or {}
    author = (commit.get("author") or {})
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


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)
