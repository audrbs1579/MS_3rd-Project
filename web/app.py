import os
import json
import base64
import logging
import requests
from datetime import datetime, timezone, timedelta
from urllib.parse import urlencode, urljoin

from flask import (
    Flask, render_template, request, redirect, session,
    url_for, jsonify, Response
)

# =========================
# 기본 설정 / 환경변수
# =========================
app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev-secret")

# GitHub OAuth
GITHUB_CLIENT_ID = os.environ.get("GITHUB_CLIENT_ID", "")
GITHUB_CLIENT_SECRET = os.environ.get("GITHUB_CLIENT_SECRET", "")
# 기본값을 배포 도메인으로 교체 (원하면 GITHUB_REDIRECT_URI로 덮어쓰기)
GITHUB_REDIRECT_URI = os.environ.get(
    "GITHUB_REDIRECT_URI",
    "https://project-guardian-prod-staging-gzescxh7cmfvdbg6.koreacentral-01.azurewebsites.net/callback",
)
GITHUB_SCOPE = "repo read:user read:org"
GH_API = "https://api.github.com"

# Databricks
DATABRICKS_ENDPOINT = os.environ.get(
    "DATABRICKS_ENDPOINT",
    "https://adb-1505442256189071.11.azuredatabricks.net/serving-endpoints/ver3endpoint/invocations",
)
DATABRICKS_TOKEN = (
    os.environ.get("DATABRICKS_TOKEN")
    or os.environ.get("DATABRICKS_PAT")
)
DATABRICKS_TIMEOUT = int(os.environ.get("DATABRICKS_TIMEOUT", "20"))

# 서버
PORT = int(os.environ.get("PORT", "8000"))
BIND = os.environ.get("BIND", "0.0.0.0")

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("guardian")

# =========================
# 공통 유틸
# =========================
def gh_headers():
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "project-guardian"}
    tok = session.get("access_token")
    if tok:
        headers["Authorization"] = f"Bearer {tok}"
    return headers

def gh_get(path: str, params=None):
    url = urljoin(GH_API + "/", path.lstrip("/"))
    r = requests.get(url, headers=gh_headers(), params=params or {}, timeout=15)
    r.raise_for_status()
    return r.json()

def safe_iso(dt_str):
    if not dt_str:
        return None
    try:
        return datetime.fromisoformat(dt_str.replace("Z", "+00:00")).astimezone(timezone.utc)
    except Exception:
        return None

# =========================
# 라우팅: 페이지
# =========================
@app.route("/")
def index():
    if not session.get("access_token"):
        return render_template("index.html")
    return redirect(url_for("loading"))

@app.route("/login")
def login():
    state = base64.urlsafe_b64encode(os.urandom(24)).decode("utf-8")
    session["oauth_state"] = state
    params = {
        "client_id": GITHUB_CLIENT_ID,
        "redirect_uri": GITHUB_REDIRECT_URI,
        "scope": GITHUB_SCOPE,
        "state": state,
    }
    return redirect("https://github.com/login/oauth/authorize?" + urlencode(params))

@app.route("/callback")
def callback():
    code = request.args.get("code")
    state = request.args.get("state")
    if not code or not state or state != session.get("oauth_state"):
        return "Invalid OAuth state", 400

    token_url = "https://github.com/login/oauth/access_token"
    headers = {"Accept": "application/json"}
    data = {
        "client_id": GITHUB_CLIENT_ID,
        "client_secret": GITHUB_CLIENT_SECRET,
        "code": code,
        "redirect_uri": GITHUB_REDIRECT_URI,
    }
    r = requests.post(token_url, headers=headers, data=data, timeout=15)
    r.raise_for_status()
    token_json = r.json()
    access_token = token_json.get("access_token")
    if not access_token:
        return "Failed to obtain access token", 400

    session["access_token"] = access_token
    return redirect(url_for("loading"))

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))

@app.route("/loading")
def loading():
    if not session.get("access_token"):
        return redirect(url_for("index"))
    return render_template("loading.html")

@app.route("/dashboard")
def dashboard():
    if not session.get("access_token"):
        return redirect(url_for("index"))
    return render_template("dashboard_branch.html")

@app.route("/detail")
def detail():
    if not session.get("access_token"):
        return redirect(url_for("index"))
    return render_template("detail_view.html")

@app.route("/results")
def results():
    if not session.get("access_token"):
        return redirect(url_for("index"))
    return render_template("results.html")

# =========================
# Databricks 호출/정규화
# =========================
def call_databricks(features: dict) -> dict:
    if not (DATABRICKS_ENDPOINT and DATABRICKS_TOKEN):
        raise RuntimeError("Databricks 설정 누락(DATABRICKS_ENDPOINT / DATABRICKS_TOKEN).")

    body = {"dataframe_records": [features]}
    headers = {
        "Authorization": f"Bearer {DATABRICKS_TOKEN}",
        "Content-Type": "application/json",
    }
    resp = requests.post(
        DATABRICKS_ENDPOINT, headers=headers, json=body, timeout=DATABRICKS_TIMEOUT
    )
    resp.raise_for_status()
    data = resp.json()

    # 응답 정규화: anomaly_score / is_anomaly / threshold_used
    # Databricks는 {predictions:[{...}]}, 혹은 바로 dict로 줄 수 있음
    rec = None
    if isinstance(data, dict) and "predictions" in data:
        preds = data.get("predictions") or []
        rec = preds[0] if preds else {}
    elif isinstance(data, list):
        rec = data[0] if data else {}
    elif isinstance(data, dict):
        rec = data
    else:
        rec = {}

    def pick(keys, src):
        for k in keys:
            if isinstance(src, dict) and k in src:
                return src[k]
        return None

    score = pick(["anomaly_score", "_anomaly_score", "score"], rec)
    is_anom = pick(["is_anomaly", "_is_anomaly", "is_outlier"], rec)
    thr = pick(["threshold_used", "threshold"], rec)

    # 타입 캐스팅
    score = float(score) if score is not None else None
    if isinstance(is_anom, str):
        is_anom = is_anom.lower() in ("true", "1", "yes")
    elif isinstance(is_anom, (int, float)):
        is_anom = bool(is_anom)
    thr = float(thr) if thr is not None else None

    return {
        "anomaly_score": score,
        "is_anomaly": is_anom,
        "threshold_used": thr,
        "raw": data,
    }

# =========================
# GitHub → 피처 구성
# =========================
SENSITIVE_KEYWORDS = [
    "secret","secrets","token","passwd","password","credential","private","key",
    ".pem",".pfx",".p12",".cer",".crt",".der",".keystore",".jks","id_rsa",".env","config"
]

def is_sensitive(files) -> float:
    for f in files or []:
        name = (f.get("filename") or "").lower()
        for kw in SENSITIVE_KEYWORDS:
            if kw in name:
                return 1.0
    return 0.0

def q90_push_size(repo_events) -> float:
    vals = [int(e.get("payload", {}).get("size", 0)) for e in repo_events if e.get("type")=="PushEvent"]
    if not vals:
        return 0.0
    vals.sort()
    idx = int(0.9 * (len(vals)-1))
    return float(vals[idx])

def build_features(repo_full: str, sha: str, branch: str|None) -> dict:
    c = gh_get(f"/repos/{repo_full}/commits/{sha}")
    commit = (c or {}).get("commit", {})
    files = (c or {}).get("files", []) or []
    author_dt = safe_iso(commit.get("author", {}).get("date")) or safe_iso(commit.get("committer", {}).get("date"))
    created_at_ts = int(author_dt.timestamp()) if author_dt else 0
    hour = author_dt.hour if author_dt else 0

    additions = sum(int(f.get("additions", 0)) for f in files)
    deletions = sum(int(f.get("deletions", 0)) for f in files)
    push_size = float(additions + deletions)
    push_distinct = float(len(files))
    sensitive = is_sensitive(files)

    # 메인라인 여부: 기본 브랜치와 동일한지 비교
    try:
        repo = gh_get(f"/repos/{repo_full}")
        default_branch = (repo or {}).get("default_branch", "main")
        ref_is_mainline = 1.0 if (branch or "").lower() == (default_branch or "").lower() else 0.0
    except Exception:
        ref_is_mainline = 0.0

    # 활동 카운트
    actor_login = ((c.get("author") or {}).get("login")
                   or (c.get("committer") or {}).get("login"))
    try:
        user_events = gh_get(f"/users/{actor_login}/events/public", params={"per_page": 100}) if actor_login else []
    except Exception:
        user_events = []
    try:
        repo_events = gh_get(f"/repos/{repo_full}/events", params={"per_page": 100})
    except Exception:
        repo_events = []
    actor_events_total = len(user_events)
    repo_events_total = len(repo_events)
    actor_hour_events = 0
    for e in user_events:
        ts = safe_iso(e.get("created_at"))
        if ts and ts.hour == hour:
            actor_hour_events += 1
    actor_repo_events = sum(1 for e in user_events if (e.get("repo") or {}).get("name", "").lower()==repo_full.lower())

    # org 계수는 퍼블릭 권한 이슈가 많아 방어적으로 0
    org_events_total = 0
    actor_org_events = 0

    repo_push_q90 = q90_push_size(repo_events)
    actor_hour_ratio = float(actor_hour_events) / float(actor_events_total or 1)

    return {
        "type": "push",
        "created_at_ts": int(created_at_ts),
        "hour": int(hour),
        "push_size": float(push_size),
        "push_distinct": float(push_distinct),
        "ref_is_mainline": float(ref_is_mainline),
        "is_sensitive_type": float(sensitive),
        "actor_events_total": int(actor_events_total),
        "repo_events_total": int(repo_events_total),
        "org_events_total": int(org_events_total),
        "actor_repo_events": int(actor_repo_events),
        "actor_org_events": int(actor_org_events),
        "actor_hour_events": int(actor_hour_events),
        "repo_push_q90": float(repo_push_q90),
        "actor_hour_ratio": float(actor_hour_ratio),
    }

# =========================
# API
# =========================
@app.get("/api/security_status")
def api_security_status():
    if not session.get("access_token"):
        return jsonify({"error": "unauthorized"}), 401
    repo = request.args.get("repo")
    sha = request.args.get("sha")
    branch = request.args.get("branch")
    if not repo or not sha:
        return jsonify({"error": "missing params"}), 400

    try:
        feats = build_features(repo, sha, branch)
        model = call_databricks(feats) if feats else None
        # 프런트가 기대하는 3개만 깔끔히 전달
        resp = {
            "repo": repo,
            "sha": sha,
            "features": feats,
            "bricks": {
                "anomaly_score": (model or {}).get("anomaly_score"),
                "is_anomaly": (model or {}).get("is_anomaly"),
                "threshold_used": (model or {}).get("threshold_used"),
            },
        }
        return jsonify(resp)
    except requests.HTTPError as he:
        log.exception("security_status http error")
        return jsonify({"error": "http_error", "detail": str(he), "body": getattr(he, "response", None).text if hasattr(he, "response") and he.response is not None else ""}), 502
    except Exception as e:
        log.exception("security_status error")
        return jsonify({"error": "runtime_error", "detail": str(e)}), 500

# (필요한 다른 API는 기존 파일 그대로 사용)

# =========================
# 엔트리포인트
# =========================
@app.get("/health")
def health():
    return {"ok": True, "ts": int(datetime.now(timezone.utc).timestamp())}

if __name__ == "__main__":
    app.run(host=BIND, port=PORT, debug=False)
