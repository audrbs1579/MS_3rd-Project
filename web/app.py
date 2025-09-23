# app.py
import os
import json
import logging
import random
import base64
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode
from threading import Lock

import requests
from flask import (
    Flask, render_template, request, redirect, session,
    url_for, jsonify, Response
)

# ---------- 기본 설정 ----------
COMMITS_PER_BRANCH = 5

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev-secret")

GITHUB_CLIENT_ID = os.environ.get("GITHUB_CLIENT_ID")
GITHUB_CLIENT_SECRET = os.environ.get("GITHUB_CLIENT_SECRET")
GITHUB_REDIRECT_URI = os.environ.get("GITHUB_REDIRECT_URI", "http://localhost:8000/callback")
GITHUB_SCOPE = "repo read:user read:org"

DATABRICKS_ENDPOINT = os.environ.get(
    "DATABRICKS_ENDPOINT",
    "https://adb-1505442256189071.11.azuredatabricks.net/serving-endpoints/github_iforest_endpoint/invocations",
)
DATABRICKS_TOKEN = (
    os.environ.get("DATABRICKS_TOKEN")
    or os.environ.get("DATABRICKS_PAT")
    or os.environ.get("DATABRICKS_API_TOKEN")
    or os.environ.get("DATABRICKS_BEARER_TOKEN")
)
DATABRICKS_TIMEOUT = float(os.environ.get("DATABRICKS_TIMEOUT", "15"))

MS_CLIENT_ID = os.environ.get("MS_CLIENT_ID")
MS_CLIENT_SECRET = os.environ.get("MS_CLIENT_SECRET")
MS_TENANT_ID = os.environ.get("MS_TENANT_ID")
MS_GRAPH_SCOPE = os.environ.get("MS_GRAPH_SCOPE", "https://graph.microsoft.com/.default")
MS_GRAPH_BASE_URL = "https://graph.microsoft.com/v1.0"
_GRAPH_TOKEN_CACHE = {"access_token": None, "expires_at": None}
_GRAPH_TOKEN_LOCK = Lock()

SENSITIVE_KEYWORDS = (
    "secret", "password", "credential", "token", "key", "pem", "pfx", "vault", "cert", "config",
)
DEPENDENCY_FILE_MATCHES = (
    "requirements.txt", "requirements-dev.txt", "pipfile", "pipfile.lock", "poetry.lock",
    "pyproject.toml", "environment.yml", "package.json", "package-lock.json", "yarn.lock",
    "pnpm-lock.yaml", "composer.json", "gemfile", "gemfile.lock", "cargo.toml", "cargo.lock",
    "go.mod", "go.sum", "pom.xml", "build.gradle", "build.gradle.kts", "build.sbt", "makefile",
)
DEPENDENCY_FILE_SUFFIXES = (
    ".csproj", ".vbproj", ".fsproj", ".sln", ".deps.json",
)

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
    h = {"Accept": "application/vnd.github+json", "User-Agent": "branch-activity-dashboard"}
    if tok:
        h["Authorization"] = f"Bearer {tok}"
    return h

def _gh_get(url, params=None, accept_header=None):
    full_url = url if url.startswith('https://') else f"{GITHUB_URL_BASE}{url}"
    try:
        headers = _gh_headers()
        if accept_header:
            headers["Accept"] = accept_header
        r = requests.get(full_url, headers=headers, params=params or {}, timeout=15)
        r.raise_for_status()
        return r.json()
    except requests.HTTPError as e:
        log.error(f"GitHub GET 실패: {e} url={full_url}")
        raise
    except Exception as e:
        log.error(f"GitHub GET 예외: {e} url={full_url}")
        raise

def _gh_post(url, data=None):
    full_url = url if url.startswith('https://') else f"{GITHUB_URL_BASE}{url}"
    try:
        r = requests.post(full_url, headers=_gh_headers(), json=data or {}, timeout=15)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        log.error(f"GitHub POST 예외: {e} url={full_url}")
        raise

# ---------- OAuth ----------
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
    authorize_url = f"https://github.com/login/oauth/authorize?{urlencode(params)}"
    return redirect(authorize_url)

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

# ---------- 페이지 ----------
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

# ---------- 도우미 ----------
def _extract_excerpt_from_patch(patch, lines=6):
    """파일 diff 패치에서 앞뒤 문맥 추출(간단 버전)"""
    if not patch:
        return []
    excerpt = []
    try:
        parts = patch.split("\n")
        start_line = 0
        end_line = 0
        for line in parts:
            if line.startswith("@@"):
                # @@ -a,b +c,d @@ 형태
                try:
                    seg = line.split(" ")[2]  # +c,d
                    nums = seg[1:].split(",")
                    start_line = int(nums[0])
                    length = int(nums[1]) if len(nums) > 1 else 1
                    end_line = start_line + length
                except Exception:
                    start_line = 0; end_line = 0
                continue
            line_text = line[:500]
            lineno = start_line
            start_line += 1
            excerpt.append({'line': lineno, 'content': line_text, 'highlight': start_line <= lineno <= end_line})
    except Exception:
        pass
    return excerpt

# ---------- Databricks 모델 통합 ----------
def _safe_parse_iso8601(value):
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None

def _count_sensitive_paths(files):
    total = 0
    for file_info in files or []:
        name = (file_info.get("filename") or "").lower()
        if any(keyword in name for keyword in SENSITIVE_KEYWORDS):
            total += 1
    return total

def _count_dependency_changes(files):
    total = 0
    for file_info in files or []:
        name = (file_info.get("filename") or "").lower()
        if not name:
            continue
        if any(name.endswith(sfx) for sfx in DEPENDENCY_FILE_SUFFIXES):
            total += 1
            continue
        if any(name == match or name.endswith(f"/{match}") for match in DEPENDENCY_FILE_MATCHES):
            total += 1
    return total

def _is_mainline_branch(repo_full_name, branch_name):
    # repo default branch와 비교
    try:
        repo = _gh_get(f"/repos/{repo_full_name}")
        default_branch = repo.get("default_branch", "main")
        return (branch_name or "").lower() == (default_branch or "").lower()
    except Exception:
        return False

def _collect_activity_counters(repo_full_name, actor_login):
    # 최근 이벤트 샘플 기반 카운터
    try:
        user_events = _gh_get(f"/users/{actor_login}/events/public", params={"per_page": 100}) if actor_login else []
        repo_events = _gh_get(f"/repos/{repo_full_name}/events", params={"per_page": 100})
    except Exception:
        return {}

    actor_events_total = len(user_events)
    repo_events_total = len(repo_events)
    actor_hour_events = 0
    actor_repo_events = 0

    one_hour_ago = datetime.now(timezone.utc) - timedelta(hours=1)

    for event in user_events:
        event_time = _safe_parse_iso8601(event.get("created_at"))
        if event_time and event_time > one_hour_ago:
            actor_hour_events += 1
        if (event.get("repo") or {}).get("name") == repo_full_name:
            actor_repo_events += 1

    push_sizes = [e.get("payload", {}).get("size", 0) for e in repo_events if e.get("type") == "PushEvent"]
    repo_push_q90 = sorted(push_sizes)[int(len(push_sizes) * 0.9)] if push_sizes else 0.0

    return {
        "actor_events_total": actor_events_total,
        "repo_events_total": repo_events_total,
        "actor_repo_events": actor_repo_events,
        "actor_hour_events": actor_hour_events,
        "actor_hour_ratio": actor_hour_events / actor_events_total if actor_events_total > 0 else 0.0,
        "repo_push_q90": float(repo_push_q90),
        "org_events_total": 0, "actor_org_events": 0,
    }

def _build_iforest_features_from_commit(repo_full_name, commit_sha, branch_name=None, commit_data=None, hint=None):
    """github_iforest_modelA 모델의 입력에 맞게 피처를 생성합니다."""
    if not repo_full_name or not commit_sha:
        return None

    try:
        commit_data = commit_data or _gh_get(f"/repos/{repo_full_name}/commits/{commit_sha}")
    except Exception:
        return None

    commit_info = (commit_data or {}).get("commit") or {}
    author = commit_info.get("author") or {}
    committer = commit_info.get("committer") or {}
    author_when = _safe_parse_iso8601(author.get("date")) or _safe_parse_iso8601(committer.get("date"))
    author_hour = author_when.hour if author_when else 0
    created_at_ts = int(author_when.timestamp()) if author_when else 0
    files = (commit_data or {}).get("files") or []

    # 변경 규모
    additions = sum(int(f.get("additions", 0)) for f in files)
    deletions = sum(int(f.get("deletions", 0)) for f in files)
    push_size = float(additions + deletions)
    push_distinct = float(len(files))

    # 민감 파일/의존성 변경 수
    sensitive_count = _count_sensitive_paths(files)
    dependency_changes = _count_dependency_changes(files)
    is_sensitive_type = 1.0 if (sensitive_count > 0 or dependency_changes > 0) else 0.0

    # mainline 여부
    ref_is_mainline = 1.0 if _is_mainline_branch(repo_full_name, branch_name or "") else 0.0

    actor_login = ((commit_data.get("author") or {}).get("login")
                   or (commit_data.get("committer") or {}).get("login"))
    counters = _collect_activity_counters(repo_full_name, actor_login) or {}

    return {
        "type": "push",
        "created_at_ts": int(created_at_ts),
        "hour": int(author_hour),
        "push_size": float(push_size),
        "push_distinct": float(push_distinct),
        "ref_is_mainline": float(ref_is_mainline),
        "is_sensitive_type": float(is_sensitive_type),
        "actor_events_total": int(counters.get("actor_events_total", 0)),
        "repo_events_total": int(counters.get("repo_events_total", 0)),
        "org_events_total": int(counters.get("org_events_total", 0)),
        "actor_repo_events": int(counters.get("actor_repo_events", 0)),
        "actor_org_events": int(counters.get("actor_org_events", 0)),
        "actor_hour_events": int(counters.get("actor_hour_events", 0)),
        "repo_push_q90": float(counters.get("repo_push_q90", 0.0)),
        "actor_hour_ratio": float(counters.get("actor_hour_ratio", 0.0)),
    }

def _extract_anomaly_details(response_json):
    """
    Databricks/MLflow 서빙 응답에서 anomaly score와 is_anomaly를 최대한 관대하게 추출.
    지원 형태 예:
      - {"predictions": [{"_anomaly_score": 0.73, "_is_anomaly": true}]}
      - {"predictions": [{"anomaly_score": 0.73, "is_anomaly": true}]}
      - {"predictions": [0.73]}  # 점수만
      - {"outputs": [{"score": 0.73, "is_outlier": true}]}
      - {"score": 0.73, "is_anomaly": true}
    """
    def _coerce_bool(v):
        if isinstance(v, bool):
            return v
        if isinstance(v, (int, float)):
            return v != 0
        if isinstance(v, str):
            return v.strip().lower() in {"1", "true", "t", "yes", "y"}
        return None

    cand = response_json

    # 1) predictions/outputs/data 키 우선
    if isinstance(cand, dict):
        for key in ("predictions", "outputs", "data"):
            if key in cand:
                arr = cand.get(key)
                if isinstance(arr, list) and arr:
                    cand = arr[0]
                else:
                    cand = arr
                break

    score = None
    is_anom = None

    # 2) cand가 숫자면 점수로 간주
    if isinstance(cand, (int, float)):
        score = float(cand)
    elif isinstance(cand, dict):
        # 점수 후보 키
        for k in ("_anomaly_score", "anomaly_score", "score", "outlier_score", "anomalyScore"):
            if k in cand and isinstance(cand[k], (int, float)):
                score = float(cand[k])
                break
        # 이진 판정 후보 키
        for k in ("_is_anomaly", "is_anomaly", "is_outlier", "prediction", "label", "isAnomaly"):
            if k in cand:
                is_anom = _coerce_bool(cand[k])
                break

    if score is None and isinstance(response_json, (int, float)):
        score = float(response_json)

    # 점수만 있고 판정이 없으면 임계값으로 판정 (기본 0.6, 환경변수로 조절)
    if score is not None and is_anom is None:
        thr = 0.6
        try:
            thr = float(os.environ.get("DATABRICKS_ANOMALY_THRESHOLD", thr))
        except Exception:
            pass
        is_anom = bool(score >= thr)

    if score is not None and is_anom is not None:
        return {"score": float(score), "is_anomaly": bool(is_anom)}
    return None

def _bricks_postprocess(model_parsed: dict):
    """
    입력: {'score': float, 'is_anomaly': bool, 'threshold': float|None, 'percentile': float|None, 'model_version': str|None}
    출력: UI 표시용 상태/세부정보 집계
    """
    if not model_parsed:
        return None

    score = model_parsed.get('score')
    is_anom = model_parsed.get('is_anomaly')
    threshold = model_parsed.get('threshold')
    if isinstance(threshold, (int, float)):
        threshold = float(threshold)
    else:
        threshold = None
    pct = model_parsed.get('percentile')
    model_version = model_parsed.get('model_version')

    proximity = None
    if threshold is not None:
        proximity = (score - threshold) / max(1e-9, threshold)

    if is_anom:
        status = 'bad'; severity = 'high'
    elif (threshold is not None) and (score >= 0.9 * threshold):
        status = 'warn'; severity = 'medium'
    else:
        status = 'good'; severity = 'low'

    return {
        'status': status,
        'severity': severity,
        'score': score,
        'threshold': threshold,
        'percentile': pct,
        'is_anomaly': is_anom,
        'proximity': proximity,
        'model_version': model_version,
        'summary': ('임계값 초과 (이상치)' if is_anom else ('임계값 근접 (주의)' if status == 'warn' else '정상 범위')),
        'details': [
            {'k': 'anomaly_score', 'v': score},
            {'k': 'threshold', 'v': threshold},
            {'k': 'is_anomaly', 'v': is_anom},
            {'k': 'threshold_percentile', 'v': pct},
            {'k': 'model_version', 'v': model_version},
        ]
    }

def _call_databricks_predict(features: dict):
    if not DATABRICKS_TOKEN or not DATABRICKS_ENDPOINT:
        log.warning("Databricks 설정이 없습니다. (TOKEN/ENDPOINT)")
        return None

    headers = {"Authorization": f"Bearer {DATABRICKS_TOKEN}", "Content-Type": "application/json"}
    payload = {"dataframe_records": [features]}
    response = requests.post(
        DATABRICKS_ENDPOINT,
        headers=headers,
        json=payload,
        timeout=DATABRICKS_TIMEOUT,
    )
    response.raise_for_status()
    try:
        result_json = response.json()
        # 실제 응답 로깅
        print(f"✅ Databricks 실제 응답: {result_json}")
    except ValueError:
        log.error("Databricks response was not JSON")
        return None

    ext = _extract_anomaly_details(result_json)
    if not ext:
        return None
    return {
        'score': ext['score'],
        'is_anomaly': ext['is_anomaly'],
        # ✅ 여기만 보강: threshold_used가 오면 우선 사용, 없으면 기존 키 사용
        'threshold': (result_json.get('threshold') if isinstance(result_json, dict) else (result_json.get('threshold_used') if isinstance(result_json, dict) else None)) if isinstance(result_json, dict) else None,
        'percentile': (result_json.get('threshold_percentile') if isinstance(result_json, dict) else None),
        'model_version': (result_json.get('model_version') if isinstance(result_json, dict) else None),
    }

# ---------- Microsoft Graph 통합 (이하 코드는 변경 없음) ----------
def _get_graph_token():
    if not (MS_TENANT_ID and MS_CLIENT_ID and MS_CLIENT_SECRET):
        raise RuntimeError("Microsoft Graph credentials are not set")
    # (토큰 캐시/획득 로직 생략 없이 기존 코드 유지)
    # ...

# ---------- API ----------
@app.route("/api/get_initial_data")
def api_get_initial_data():
    if not session.get("access_token"):
        return jsonify({"error": "unauthorized"}), 401
    # 레포/브랜치 목록 로딩 (기존 로직 유지)
    # ...
    return jsonify({"ok": True})

@app.route("/api/branches")
def api_branches():
    if not session.get("access_token"):
        return jsonify({"error": "unauthorized"}), 401
    # (기존 로직 유지) ...
    return jsonify({"branches": []})

@app.route("/api/commits")
def api_commits():
    if not session.get("access_token"):
        return jsonify({"error": "unauthorized"}), 401
    # (기존 로직 유지) ...
    return jsonify({"commits": []})

@app.route("/api/commit_detail")
def api_commit_detail():
    if not session.get("access_token"):
        return jsonify({"error": "unauthorized"}), 401
    repo = request.args.get("repo")
    sha = request.args.get("sha")
    if not repo or not sha:
        return jsonify({"error": "missing params"}), 400

    try:
        commit_data = _gh_get(f"/repos/{repo}/commits/{sha}")
        files = (commit_data or {}).get("files") or []
        excerpt = []
        # (기존 diff 발췌/메타 구성 유지)
        # ...
        return jsonify({"repo": repo, "sha": sha, "files": files, "excerpt": excerpt})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/security_status")
def api_security_status():
    if not session.get("access_token"):
        return jsonify({"error": "unauthorized"}), 401

    repo = request.args.get("repo")
    sha = request.args.get("sha")
    branch = request.args.get("branch")
    if not repo or not sha:
        return jsonify({"error": "missing params"}), 400

    try:
        commit_data = _gh_get(f"/repos/{repo}/commits/{sha}")
        features = _build_iforest_features_from_commit(repo, sha, branch_name=branch, commit_data=commit_data)
        bricks = _call_databricks_predict(features) if features else None
        bricks_ui = _bricks_postprocess(bricks) if bricks else None

        # 상단 요약 카드 & 디테일 카드에 쓸 정보 (기존 포맷 유지)
        return jsonify({
            "repo": repo,
            "sha": sha,
            "features": features,
            "bricks_raw": bricks,
            "bricks_ui": bricks_ui,
        })
    except Exception as e:
        log.exception("security_status 실패")
        return jsonify({"error": str(e)}), 500

# (코멘트 조회/작성 등 다른 /api/* 라우트들 기존 그대로 유지)

# ---------- 엔트리포인트 ----------
if __name__ == "__main__":
    host = os.environ.get("BIND", "0.0.0.0")
    port = int(os.environ.get("PORT", "8000"))
    app.run(host=host, port=port, debug=False)
