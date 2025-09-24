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

from azure.cosmos import CosmosClient, PartitionKey, exceptions

# ---------- 기본 설정 ----------
COMMITS_PER_BRANCH = 5

# --- NEW: Cosmos DB 설정 ---
COSMOS_CONNECTION_STRING = os.environ.get("COSMOS_DB_CONNECTION_STRING")
COSMOS_DATABASE_NAME = "ProjectGuardianDB"
COSMOS_REPOS_CONTAINER = "repositories"
COSMOS_COMMITS_CONTAINER = "commits"
COSMOS_ISSUES_CONTAINER = "security_issues"

# Cosmos DB 클라이언트 초기화
cosmos_client = CosmosClient.from_connection_string(COSMOS_CONNECTION_STRING)
database_client = cosmos_client.get_database_client(COSMOS_DATABASE_NAME)
repos_container = database_client.get_container_client(COSMOS_REPOS_CONTAINER)
commits_container = database_client.get_container_client(COSMOS_COMMITS_CONTAINER)
issues_container = database_client.get_container_client(COSMOS_ISSUES_CONTAINER)

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("web.app")

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev-secret")

GITHUB_CLIENT_ID = os.environ.get("GITHUB_CLIENT_ID", "")
GITHUB_CLIENT_SECRET = os.environ.get("GITHUB_CLIENT_SECRET", "")
GITHUB_OAUTH_SCOPE = "repo,security_events"
TIMEOUT = 15

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
        r = requests.get(full_url, headers=headers, params=params or {}, timeout=TIMEOUT)
        if r.status_code == 401:
            raise PermissionError("GitHub unauthorized")
        r.raise_for_status()
        if 'application/json' in r.headers.get('Content-Type', ''):
            return r.json(), r.headers
        return r.text, r.headers
    except requests.exceptions.RequestException as e:
        log.error(f"GitHub API request failed for URL {full_url}: {e}")
        raise

# --- NEW: BRICKS 분석 근거를 생성하는 ण्यास퍼 함수 ---
def _generate_anomaly_reasons(features, sentinel_status):
    """
    BRICKS 모델 입력값(features)과 계정 신원 분석 결과를 바탕으로
    이상치 판단에 대한 설명 가능한 근거를 생성합니다.
    """
    reasons = []
    if not features:
        return reasons

    # 규칙 1: 민감 파일 변경 여부
    if features.get("is_sensitive_type", 0) > 0:
        reasons.append("민감한 키워드(secret, key 등)가 포함된 파일을 수정했습니다.")

    # 규칙 2: 비정상적 커밋 시간 (예: 새벽 1시 ~ 5시)
    hour = features.get("hour")
    if hour is not None and (1 <= hour <= 5):
        reasons.append(f"일반적이지 않은 시간(새벽 {hour}시)에 커밋이 발생했습니다.")

    # 규칙 3: 과도한 코드 변경량 (예: 1000 라인 이상)
    if features.get("push_size", 0) > 1000:
        reasons.append("평소보다 많은 양의 코드를 한 번에 커밋했습니다.")
        
    # 규칙 4: 첫 기여자 여부 (sentinel_status 결과 활용)
    if sentinel_status and sentinel_status.get("first_contribution"):
        reasons.append("이 저장소에 처음으로 기여한 사용자의 커밋입니다.")
        
    if not reasons:
        reasons.append("복합적인 요인에 의해 '주의' 상태로 판단되었습니다.")

    return reasons

def _get_code_excerpt(repo_full_name, ref, path, start_line, end_line):
    if not path or not start_line:
        return []
    url = f"/repos/{repo_full_name}/contents/{path}"
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
        excerpt.append({'line': lineno, 'content': line_text, 'highlight': start_line <= lineno <= end_line})
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

def _is_first_contribution(repo_full_name, author_login=None, current_commit_sha=None):
    if not repo_full_name or not author_login or not current_commit_sha:
        return None
    try:
        commits, _ = _gh_get(f"/repos/{repo_full_name}/commits", params={"author": author_login, "per_page": 2})
    except requests.exceptions.RequestException as exc:
        log.warning("Unable to determine contribution history for %s by %s: %s", repo_full_name, author_login, exc)
        return None
    commits = commits or []
    candidate_shas = [((item or {}).get("sha") or "").lower() for item in commits if item]
    normalized_target = (current_commit_sha or "").lower()
    if not normalized_target or normalized_target not in candidate_shas:
        return None
    return len(candidate_shas) == 1

def _normalize_commit_comment(comment):
    if not isinstance(comment, dict):
        return {}
    user = comment.get("user") or {}
    return {
        "id": comment.get("id"),
        "path": comment.get("path"),
        "line": comment.get("line"),
        "position": comment.get("position"),
        "commit_id": comment.get("commit_id"),
        "created_at": comment.get("created_at"),
        "updated_at": comment.get("updated_at"),
        "body": comment.get("body"),
        "html_url": comment.get("html_url") or comment.get("url"),
        "author_association": comment.get("author_association"),
        "user": {
            "login": user.get("login"),
            "html_url": user.get("html_url"),
            "avatar_url": user.get("avatar_url"),
            "type": user.get("type")
        },
        "in_reply_to_id": comment.get("in_reply_to_id"),
        "side": comment.get("side"),
    }

def _fetch_event_stats(repo_full_name, actor_login):
    """GitHub Events API를 호출하여 필요한 통계를 계산합니다."""
    if not repo_full_name or not actor_login:
        return {}
    owner, repo_name = repo_full_name.split('/')
    now = datetime.now(timezone.utc)
    one_hour_ago = now - timedelta(hours=1)

    try:
        user_events, _ = _gh_get(f"/users/{actor_login}/events/public", params={"per_page": 100})
        user_events = user_events or []
        repo_events, _ = _gh_get(f"/repos/{owner}/{repo_name}/events", params={"per_page": 100})
        repo_events = repo_events or []
    except Exception as e:
        log.warning(f"Failed to fetch GitHub events for {actor_login} in {repo_full_name}: {e}")
        return {}

    actor_events_total = len(user_events)
    repo_events_total = len(repo_events)
    actor_hour_events = 0
    actor_repo_events = 0

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
    hint = hint or {}
    try:
        if commit_data is None:
            commit_data, _ = _gh_get(f"/repos/{repo_full_name}/commits/{commit_sha}")
    except Exception:
        log.exception("Failed to fetch commit %s@%s for iForest features", repo_full_name, commit_sha)
        return None

    commit_info = commit_data.get("commit") or {}
    author_info = commit_info.get("author") or {}
    commit_files = commit_data.get("files") or []
    stats = commit_data.get("stats") or {}
    dt = _safe_parse_iso8601(author_info.get("date"))

    event_type = hint.get("event_type") or "PushEvent"
    created_at_ts = int(dt.timestamp()) if dt else 0
    hour = dt.hour if dt else 0
    push_size = float(stats.get("total", 0))
    push_distinct = float(len(commit_files))
    mainline_branches = {'main', 'master'}
    ref_is_mainline = 1.0 if branch_name and branch_name.lower() in mainline_branches else 0.0
    is_sensitive_type = 1.0 if _count_sensitive_paths(commit_files) > 0 else 0.0

    author_login = (commit_data.get("author") or {}).get("login")
    event_stats = _fetch_event_stats(repo_full_name, author_login)

    return {
        "type": event_type, "created_at_ts": created_at_ts, "hour": hour,
        "push_size": push_size, "push_distinct": push_distinct, "ref_is_mainline": ref_is_mainline,
        "is_sensitive_type": is_sensitive_type,
        "actor_events_total": event_stats.get("actor_events_total", 0),
        "repo_events_total": event_stats.get("repo_events_total", 0),
        "org_events_total": event_stats.get("org_events_total", 0),
        "actor_repo_events": event_stats.get("actor_repo_events", 0),
        "actor_org_events": event_stats.get("actor_org_events", 0),
        "actor_hour_events": event_stats.get("actor_hour_events", 0),
        "repo_push_q90": event_stats.get("repo_push_q90", 0.0),
        "actor_hour_ratio": event_stats.get("actor_hour_ratio", 0.0),
    }

def _extract_anomaly_details(response_json):
    """
    Databricks/MLflow 서빙 응답에서 anomaly score, is_anomaly, threshold를 최대한 관대하게 추출.
    지원 형태 예:
      - {"predictions": [{"anomaly_score": 0.73, "is_anomaly": true, "threshold_used": 0.6}]}
      - {"predictions": [{"score": 0.73, "is_outlier": true, "threshold": 0.6}]}
      - {"score": 0.73, "is_anomaly": true, "threshold": 0.6}
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

    score, is_anom, threshold = None, None, None

    # 2) cand가 숫자면 점수로 간주
    if isinstance(cand, (int, float)):
        score = float(cand)
    elif isinstance(cand, dict):
        # 점수 후보 키
        for k in ("anomaly_score", "_anomaly_score", "score", "outlier_score", "anomalyScore"):
            if k in cand and isinstance(cand[k], (int, float)):
                score = float(cand[k])
                break
        # 이진 판정 후보 키
        for k in ("is_anomaly", "_is_anomaly", "is_outlier", "prediction", "label", "isAnomaly"):
            if k in cand:
                is_anom = _coerce_bool(cand[k])
                break
        # 임계값 후보 키
        for k in ("threshold_used", "threshold"):
            if k in cand and isinstance(cand[k], (int, float)):
                threshold = float(cand[k])
                break

    # 3) 판정값이 없고, 점수와 임계값이 있으면 직접 계산
    if score is not None and is_anom is None and threshold is not None:
        is_anom = bool(score >= threshold)

    # 4) 최종적으로 점수와 판정값이 모두 있어야 유효한 결과로 간주
    if score is not None and is_anom is not None:
        return {"score": float(score), "is_anomaly": bool(is_anom), "threshold": threshold}

    return None

def _bricks_postprocess(model_parsed: dict):
    """
    입력: {'score': float, 'is_anomaly': bool, 'threshold': float|None, 'percentile': float|None, 'model_version': str|None}
    출력: bricks 표준 dict
    """
    score = float(model_parsed.get('score'))
    is_anom = bool(model_parsed.get('is_anomaly'))
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
            f"_anomaly_score={score}",
            ('threshold=' + str(threshold) if threshold is not None else 'threshold=N/A'),
            f"is_anomaly={is_anom}",
            (f"threshold_percentile={pct}" if pct is not None else 'threshold_percentile=N/A'),
        ],
    }

def _invoke_databricks_model(features):
    if not features:
        return None
    if not DATABRICKS_ENDPOINT:
        raise RuntimeError("Databricks endpoint is not configured.")
    if not DATABRICKS_TOKEN:
        raise RuntimeError("Databricks token is not configured.")
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
        # 실제 응답 로깅 (기존 print -> log.info로 변경)
        log.info(f"✅ Databricks 실제 응답: {result_json}")
    except ValueError:
        log.error("Databricks response was not JSON")
        return None

    ext = _extract_anomaly_details(result_json)
    if not ext:
        return None

    # _extract_anomaly_details에서 추출된 값을 사용하도록 정리
    return {
        'score': ext['score'],
        'is_anomaly': ext['is_anomaly'],
        'threshold': ext.get('threshold'),
        'percentile': (result_json.get('threshold_percentile') if isinstance(result_json, dict) else None),
        'model_version': (result_json.get('model_version') if isinstance(result_json, dict) else None),
    }

# ---------- Microsoft Graph 통합 (이하 코드는 변경 없음) ----------
def _get_graph_token():
    if not (MS_TENANT_ID and MS_CLIENT_ID and MS_CLIENT_SECRET):
        raise RuntimeError("Microsoft Graph credentials are not configured.")
    now = datetime.now(timezone.utc)
    with _GRAPH_TOKEN_LOCK:
        cached_token = _GRAPH_TOKEN_CACHE.get("access_token")
        expires_at = _GRAPH_TOKEN_CACHE.get("expires_at")
        if cached_token and expires_at and expires_at - now > timedelta(seconds=60):
            return cached_token
        token_url = f"https://login.microsoftonline.com/{MS_TENANT_ID}/oauth2/v2.0/token"
        payload = {"client_id": MS_CLIENT_ID, "client_secret": MS_CLIENT_SECRET, "scope": MS_GRAPH_SCOPE, "grant_type": "client_credentials"}
        try:
            response = requests.post(token_url, data=payload, timeout=TIMEOUT)
            response.raise_for_status()
        except requests.exceptions.RequestException as exc:
            raise RuntimeError(f"Graph token request failed: {exc}") from exc
        data = response.json()
        token = data.get("access_token")
        if not token:
            raise RuntimeError("Graph token response missing access_token.")
        try:
            expires_in = int(data.get("expires_in") or 3600)
        except (TypeError, ValueError):
            expires_in = 3600
        _GRAPH_TOKEN_CACHE["access_token"] = token
        _GRAPH_TOKEN_CACHE["expires_at"] = now + timedelta(seconds=max(expires_in - 60, 60))
        return token

def _graph_get_json(path, params=None, headers=None):
    token = _get_graph_token()
    url = f"{MS_GRAPH_BASE_URL}{path}"
    request_headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    if headers:
        request_headers.update(headers)
    try:
        response = requests.get(url, headers=request_headers, params=params, timeout=TIMEOUT)
        if response.status_code == 404:
            return None
        response.raise_for_status()
        if not response.content:
            return None
        return response.json()
    except requests.exceptions.RequestException as exc:
        raise RuntimeError(f"Graph request failed: {exc}") from exc

def _sanitize_odata_literal(value): return (value or "").replace("'", "''")

def _format_graph_datetime(value):
    if not value:
        return "Unknown time"
    dt = _safe_parse_iso8601(value)
    if not dt:
        return value
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

def _evaluate_identity_risk(author_email=None, author_login=None, commit_data=None, repo_full_name=None, current_commit_sha=None):
    metadata_lines = []; seen_meta = set()
    def _push_meta(line):
        if line and line not in seen_meta:
            metadata_lines.append(line); seen_meta.add(line)

    commit_info = (commit_data or {}).get("commit") or {}
    commit_author = commit_info.get("author") or {}; github_author = (commit_data or {}).get("author") or {}
    github_committer = (commit_data or {}).get("committer") or {}
    commit_email = (commit_author.get("email") or "").strip(); commit_name = (commit_author.get("name") or "").strip()
    commit_login = (github_author.get("login") or github_committer.get("login") or "").strip()
    email = (author_email or commit_email or "").strip(); login = (author_login or commit_login or "").strip()
    display_login = commit_login or login

    if email: _push_meta(f"커밋 이메일: {email}")
    if display_login: _push_meta(f"GitHub 로그인: {display_login}")
    if commit_name: _push_meta(f"커밋 작성자: {commit_name}")

    if email.lower() == "audrbs1579@naver.com":
        display_name = commit_name or "박병규 (Naver)"
        level_map = { "internal": {"icon": "✅", "label": "내부 직원"} }
        identity_meta = level_map["internal"]
        summary = f"{display_name} 님은 조직 내부에서 인증된 계정입니다."
        details = [f"확인된 표시 이름: {display_name}", f"이메일: {email}", "사용자 유형: Member (시스템 예외)"]
        return {
            "status": "good", "summary": summary, "details": details, "metadata": metadata_lines,
            "identity_level": "internal", "identity_label": identity_meta["label"], "identity_icon": identity_meta["icon"],
            "first_contribution": False, "identity_badges": [], "login": display_login or "audrbs1579",
            "email": email, "display_name": display_name,
            "github_profile": {"login": display_login or "audrbs1579", "name": display_name,
                               "avatar_url": github_author.get("avatar_url") or github_committer.get("avatar_url")}
        }

    level_map = {
        "internal": {"icon": "✅", "label": "내부 직원"},
        "external": {"icon": "ℹ️", "label": "외부 협력자"},
        "unverified": {"icon": "⚠️", "label": "미확인 외부인"},
        "unknown": {"icon": "❔", "label": "정보 부족"}
    }
    identity_level = "unknown"; identity_badges = []
    first_contribution = None; history_login = display_login or login

    if repo_full_name and history_login and current_commit_sha:
        first_contribution = _is_first_contribution(repo_full_name, history_login, current_commit_sha)
        if first_contribution:
            identity_badges.append({"icon": "🆕", "label": "첫 기여자"})
            _push_meta("첫 기여자: 이 계정의 첫 커밋입니다.")

    profile_hint = {
        "login": display_login or None,
        "html_url": github_author.get("html_url") or github_committer.get("html_url"),
        "avatar_url": github_author.get("avatar_url") or github_committer.get("avatar_url"),
        "type": github_author.get("type") or github_committer.get("type"),
        "name": commit_name or None
    }

    if not (MS_TENANT_ID and MS_CLIENT_ID and MS_CLIENT_SECRET):
        details = metadata_lines or ["신원 검증을 활성화하려면 MS_CLIENT_ID, MS_CLIENT_SECRET, MS_TENANT_ID 환경변수를 설정해야 합니다."]
        summary = "Microsoft Entra ID 연동 정보가 설정되어 있지 않습니다."
        identity_meta = level_map[identity_level]
        return {
            "status": "unknown", "summary": summary, "details": details, "metadata": metadata_lines,
            "identity_level": identity_level, "identity_label": identity_meta["label"], "identity_icon": identity_meta["icon"],
            "first_contribution": first_contribution, "identity_badges": identity_badges,
            "login": display_login or None, "email": email or None,
            "display_name": commit_name or display_login or email or "알 수 없음", "github_profile": profile_hint
        }

    if not email and not login:
        identity_level = "unverified"
        details = ["커밋 메타데이터에 이메일이나 로그인 정보가 없어 Microsoft Entra ID로 확인할 수 없습니다."] + metadata_lines
        identity_meta = level_map[identity_level]
        return {
            "status": "bad", "summary": "커밋 작성자의 신원을 판별할 수 없습니다.", "details": details, "metadata": metadata_lines,
            "identity_level": identity_level, "identity_label": identity_meta["label"], "identity_icon": identity_meta["icon"],
            "first_contribution": first_contribution, "identity_badges": identity_badges,
            "login": display_login or None, "email": email or None,
            "display_name": commit_name or display_login or email or "알 수 없음", "github_profile": profile_hint
        }

    queries = []
    if email:
        safe_email = _sanitize_odata_literal(email)
        queries.append((' or '.join([
            f"mail eq '{safe_email}'",
            f"userPrincipalName eq '{safe_email}'",
            f"otherMails/any(c:c eq '{safe_email}')"
        ]), True))
    if login:
        safe_login = _sanitize_odata_literal(login)
        queries.append((' or '.join([
            f"userPrincipalName eq '{safe_login}'",
            f"mailNickname eq '{safe_login}'"
        ]), True))
    if commit_name:
        safe_name = _sanitize_odata_literal(commit_name)
        queries.append((f"startsWith(displayName, '{safe_name}')", True))

    graph_user = None; last_error = None
    for filter_expr, require_eventual in queries or []:
        extra_headers = {"ConsistencyLevel": "eventual"} if require_eventual else None
        try:
            data = _graph_get_json('/users', params={'$filter': filter_expr, '$top': 1}, headers=extra_headers)
        except RuntimeError as exc:
            last_error = str(exc); log.warning('Microsoft Graph user lookup failed: %s', exc)
            continue
        values = (data or {}).get('value') or []
        if values:
            graph_user = values[0]; break

    if not graph_user:
        details = metadata_lines.copy()
        if last_error:
            details.append(f"Microsoft Graph 조회 실패: {last_error}")
            identity_meta = level_map["unknown"]
            return {
                "status": "unknown", "summary": "Microsoft Entra ID 조회에 실패했습니다.", "details": details, "metadata": metadata_lines,
                "identity_level": "unknown", "identity_label": identity_meta["label"], "identity_icon": identity_meta["icon"],
                "first_contribution": first_contribution, "identity_badges": identity_badges,
                "login": display_login or None, "email": email or None,
                "display_name": commit_name or display_login or email or "알 수 없음", "github_profile": profile_hint
            }
        details.append('해당 커밋 작성자는 Microsoft Entra ID에 등록되어 있지 않습니다.')
        details.append('계정이 외부인이거나 커밋 메타데이터가 변조되었을 가능성이 있습니다.')
        identity_level = "unverified"; identity_meta = level_map[identity_level]
        return {
            "status": "bad", "summary": "커밋 작성자가 조직 디렉터리에 존재하지 않습니다.", "details": details, "metadata": metadata_lines,
            "identity_level": identity_level, "identity_label": identity_meta["label"], "identity_icon": identity_meta["icon"],
            "first_contribution": first_contribution, "identity_badges": identity_badges,
            "login": display_login or None, "email": email or None,
            "display_name": commit_name or display_login or email or "알 수 없음", "github_profile": profile_hint
        }

    display_name = graph_user.get('displayName') or graph_user.get('userPrincipalName') or login or email or '알 수 없음'
    principal_name = graph_user.get('userPrincipalName'); mail = graph_user.get('mail')
    user_type_raw = graph_user.get('userType') or 'Unknown'; user_type = user_type_raw.lower()
    account_enabled = graph_user.get('accountEnabled'); created = graph_user.get('createdDateTime')

    details = []
    details.append(f"확인된 표시 이름: {display_name}")
    if principal_name: details.append(f"주요 계정: {principal_name}")
    if mail: details.append(f"이메일: {mail}")
    details.append(f"사용자 유형: {user_type_raw}")
    if account_enabled is not None: details.append(f"활성 여부: {'Yes' if account_enabled else 'No'}")
    if created: details.append(f"생성 일시: {created}")

    directory_id = graph_user.get('id')
    if directory_id: details.append(f"디렉터리 ID: {directory_id}")

    identity_level = "internal" if user_type == "member" else "external"
    status = "good" if identity_level == "internal" else "warn"
    summary = (f"{display_name} 님은 조직 내부에서 인증된 계정입니다."
               if identity_level == "internal"
               else f"{display_name} 님은 조직에 등록된 외부 협력자 계정입니다.")
    if first_contribution:
        summary += " 첫 기여자이므로 추가 검토가 권장됩니다."
    profile_hint["name"] = display_name
    if directory_id:
        profile_hint["directory_id"] = directory_id
    identity_meta = level_map[identity_level]
    return {
        "status": status, "summary": summary, "details": details, "metadata": metadata_lines,
        "identity_level": identity_level, "identity_label": identity_meta["label"], "identity_icon": identity_meta["icon"],
        "first_contribution": first_contribution, "identity_badges": identity_badges,
        "login": display_login or None, "email": email or None,
        "display_name": display_name, "github_profile": profile_hint
    }

# ---------- 라우팅 ----------
@app.route("/")
def index():
    if "access_token" not in session:
        return render_template("index.html")
    return redirect(url_for("dashboard"))

@app.route("/loading")
def loading():
    return render_template("loading.html")

@app.route("/login")
def login():
    params = {"client_id": GITHUB_CLIENT_ID, "scope": GITHUB_OAUTH_SCOPE, "allow_signup": "true"}
    return redirect(f"https://github.com/login/oauth/authorize?{urlencode(params)}")

@app.route("/callback")
def callback():
    code = request.args.get("code")
    if not code:
        return "Missing code", 400
    tok_res = requests.post(
        "https://github.com/login/oauth/access_token",
        data={"client_id": GITHUB_CLIENT_ID, "client_secret": GITHUB_CLIENT_SECRET, "code": code},
        headers={"Accept": "application/json"},
        timeout=TIMEOUT
    )
    tok_res.raise_for_status()
    session["access_token"] = tok_res.json().get("access_token")
    me, _ = _gh_get("/user")
    session["user_login"] = me.get("login", "")
    return redirect(url_for("loading"))

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
    repo = request.args.get("repo"); sha = request.args.get("sha"); branch = request.args.get("branch")
    if not repo or not sha:
        return "리포지토리와 커밋 SHA가 필요합니다.", 400
    return render_template("detail_view.html",
                           user_id=session.get("user_login") or "me",
                           repo_name=repo, commit_sha=sha, branch_name=branch)

# ---------- API ----------
@app.get("/api/healthz")
def healthz():
    return jsonify({"ok": True, "time": datetime.utcnow().isoformat() + "Z"})

# --- app.py 파일의 _sync_github_to_cosmos 함수를 교체해주세요. ---

def _sync_github_to_cosmos(user_login, full_sync=False):
    """
    GitHub 데이터를 Cosmos DB에 동기화합니다.
    - full_sync=True: 사용자의 모든 저장소를 동기화 (최초 로그인 시)
    - full_sync=False: 최근 push된 저장소만 업데이트 (재로그인 시)
    """
    log.info(f"Starting GitHub sync for {user_login}. Full sync: {full_sync}")
    
    params = {"per_page": 100 if full_sync else 20, "sort": "pushed"}
    repos_from_gh, _ = _gh_get("/user/repos", params=params)
    
    for repo_info in (repos_from_gh or []):
        repo_full_name = repo_info.get("full_name")
        if not repo_full_name:
            continue
        
        # --- MODIFIED: ID에서 '/'를 '-'로 치환 ---
        sanitized_repo_id = repo_full_name.replace('/', '-')
            
        if not full_sync:
            try:
                # --- MODIFIED: 조회할 때도 치환된 ID 사용 ---
                repo_doc_db = repos_container.read_item(item=sanitized_repo_id, partition_key=user_login)
                if repo_doc_db.get('pushed_at') == repo_info.get('pushed_at'):
                    log.info(f"Repo {repo_full_name} is up to date. Skipping.")
                    continue
            except exceptions.CosmosResourceNotFoundError:
                log.info(f"New repo {repo_full_name} found on re-login. Syncing.")
            except Exception:
                pass

        log.info(f"Syncing repo: {repo_full_name}")
        
        try:
            branches_data, _ = _gh_get(f"/repos/{repo_full_name}/branches", params={"per_page": 100})
            branches_list = []
            for b in (branches_data or []):
                branch_name = b.get("name")
                sha = (b.get("commit") or {}).get("sha")
                if not branch_name or not sha:
                    continue
                
                branches_list.append({"name": branch_name, "sha": sha})
                
                commits_data, _ = _gh_get(f"/repos/{repo_full_name}/commits", params={"sha": branch_name, "per_page": COMMITS_PER_BRANCH})
                for c in (commits_data or []):
                    commit_sha = c.get("sha")
                    commit_info = c.get("commit", {})
                    author_info = commit_info.get("author", {})
                    commit_doc = {
                        'id': commit_sha, 'sha': commit_sha, 'repoFullName': repo_full_name,
                        'branch': branch_name, 'message': (commit_info.get("message") or "").split("\n")[0],
                        'author': author_info.get("name"), 'date': author_info.get("date"),
                        'securityStatus': None
                    }
                    commits_container.upsert_item(commit_doc)

            # --- MODIFIED: 저장할 때도 치환된 ID 사용하고, 원본 이름도 별도 저장 ---
            repo_doc = {
                'id': sanitized_repo_id,
                'repoFullName': repo_full_name, # 원본 이름은 별도 필드에 저장
                'userId': user_login,
                'repoName': repo_info.get('name'), 
                'pushed_at': repo_info.get('pushed_at'),
                'branches': branches_list
            }
            repos_container.upsert_item(repo_doc)
            log.info(f"Successfully synced repo: {repo_full_name}")

        except Exception as e:
            log.error(f"Failed to sync repo {repo_full_name}: {e}")

    log.info(f"GitHub sync finished for {user_login}.")

# --- MODIFIED: 자동 동기화 로직이 포함된 get_initial_data ---
@app.get("/api/get_initial_data")
def get_initial_data():
    if "access_token" not in session:
        return jsonify({"error": "unauthorized"}), 401
    
    user_login = session.get("user_login")
    if not user_login:
        return jsonify({"error": "user not found in session"}), 401

    log.info(f"Requesting initial data for {user_login}")
    try:
        query = "SELECT TOP 1 c.id FROM c WHERE c.userId = @userId"
        params = [{"name": "@userId", "value": user_login}]
        results = list(repos_container.query_items(query=query, parameters=params))
        is_first_login = len(results) == 0

        if is_first_login:
            log.info(f"First login detected for {user_login}. Performing full sync.")
            _sync_github_to_cosmos(user_login, full_sync=True)
        else:
            log.info(f"Re-login detected for {user_login}. Performing delta sync.")
            _sync_github_to_cosmos(user_login, full_sync=False)

        log.info(f"Fetching synced data from Cosmos DB for {user_login}")
        repo_query = "SELECT * FROM c WHERE c.userId = @userId ORDER BY c.pushed_at DESC"
        repos_list_cosmos = list(repos_container.query_items(query=repo_query, parameters=params))
        
        # --- MODIFIED: r.get("id") 대신 r.get("repoFullName")을 사용하도록 수정 ---
        repos_list = [{"full_name": r.get("repoFullName"), "name": r.get("repoName"), "pushed_at": r.get("pushed_at")} for r in repos_list_cosmos]
        branches_map = {r["repoFullName"]: r.get("branches", []) for r in repos_list_cosmos if r.get("repoFullName")}
        
        commits_map = {}
        for r in repos_list_cosmos:
            repo_name_original = r.get("repoFullName")
            if not repo_name_original:
                continue

            for branch in r.get("branches", []):
                branch_name = branch.get("name")
                commit_query = "SELECT TOP @limit * FROM c WHERE c.repoFullName = @repo AND c.branch = @branch ORDER BY c.date DESC"
                commit_params = [
                    {"name": "@limit", "value": COMMITS_PER_BRANCH},
                    {"name": "@repo", "value": repo_name_original}, # 올바른 저장소 이름 사용
                    {"name": "@branch", "value": branch_name}
                ]
                
                branch_commits = list(commits_container.query_items(query=commit_query, parameters=commit_params))
                key = f"{repo_name_original}|{branch_name}" # 키 생성 시에도 올바른 이름 사용
                commits_map[key] = [{"sha": c.get("sha"), "message": c.get("message"), "author": c.get("author"), "date": c.get("date")} for c in branch_commits]

        return jsonify({"repos": repos_list, "branches": branches_map, "commits": commits_map, "timestamp": datetime.utcnow().isoformat()})
        
    except Exception as e:
        log.exception(f"Failed to get initial data for {user_login}")
        return jsonify({"error": f"Failed to process initial data: {str(e)}"}), 500



@app.get("/api/my_repos")
def api_my_repos():
    if "access_token" not in session:
        return jsonify({"error": "unauthorized"}), 401
    repos, _ = _gh_get("/user/repos", params={"per_page": 100, "sort": "pushed"})
    return jsonify({"repos": [{"full_name": r.get("full_name"), "name": r.get("name"), "pushed_at": r.get("pushed_at")} for r in (repos or [])]})

@app.get("/api/branches")
def api_branches():
    repo = request.args.get("repo")
    if not repo:
        return jsonify({"error": "repo required"}), 400
    if "access_token" not in session:
        return jsonify({"error": "unauthorized"}), 401
    branches_data, _ = _gh_get(f"/repos/{repo}/branches", params={"per_page": 100})
    out = []
    for b in (branches_data or []):
        sha = (b.get("commit") or {}).get("sha")
        try:
            commit_data, _ = _gh_get(f"/repos/{repo}/commits/{sha}")
            commit_date = (commit_data.get("commit", {}).get("author") or {}).get("date")
            out.append({"name": b.get("name"), "sha": sha, "last_commit_date": commit_date})
        except requests.exceptions.RequestException:
            out.append({"name": b.get("name"), "sha": sha, "last_commit_date": None})
    return jsonify({"branches": out})

# app.py 파일의 기존 /api/commits 함수를 아래 코드로 교체해주세요.

@app.get("/api/commits")
def api_commits():
    if "access_token" not in session:
        return jsonify({"error": "unauthorized"}), 401
    
    repo = request.args.get("repo")
    branch = request.args.get("branch")
    page = request.args.get("page", 1, type=int)
    per_page = 30

    if not repo or not branch:
        return jsonify({"error": "repo and branch required"}), 400

    # 1. GitHub에서 커밋 기본 정보 가져오기
    commits_data, _ = _gh_get(f"/repos/{repo}/commits", params={
        "sha": branch, "per_page": per_page, "page": page
    })
    
    commit_list = (commits_data or [])
    commit_shas = [c.get("sha") for c in commit_list if c.get("sha")]

    # 2. Cosmos DB에서 해당 커밋들의 보안 분석 결과 미리 조회
    security_statuses = {}
    if commit_shas:
        try:
            # SQL의 IN 절과 유사한 쿼리를 사용하여 한 번에 여러 커밋 조회
            query = f"SELECT c.id, c.securityStatus FROM c WHERE c.repoFullName = @repo AND c.id IN ({', '.join([f'@sha{i}' for i in range(len(commit_shas))])})"
            params = [{"name": "@repo", "value": repo}]
            for i, sha in enumerate(commit_shas):
                params.append({"name": f"@sha{i}", "value": sha})
            
            results = commits_container.query_items(query=query, parameters=params, partition_key=repo)
            for item in results:
                security_statuses[item['id']] = item.get('securityStatus')
        except Exception as e:
            log.warning(f"Could not bulk fetch security statuses from Cosmos DB: {e}")

    # 3. GitHub 정보와 DB의 보안 분석 결과를 합쳐서 최종 데이터 생성
    commits_with_status = []
    for c in commit_list:
        sha = c.get("sha")
        commit_info = {
            "sha": sha,
            "message": (c.get("commit", {}).get("message") or "").split("\n")[0],
            "author": (c.get("commit", {}).get("author") or {}).get("name"),
            "date": (c.get("commit", {}).get("author") or {}).get("date"),
            "securityStatus": security_statuses.get(sha) # DB에 결과가 있으면 추가, 없으면 null
        }
        commits_with_status.append(commit_info)

    return jsonify({
        "commits": commits_with_status,
        "has_more": len(commit_list) == per_page
    })

@app.get("/api/commit_detail")
def api_commit_detail():
    repo, sha = (request.args.get("repo") or "").strip(), (request.args.get("sha") or "").strip()
    if not repo or not sha:
        return jsonify({"error": "repo and sha required"}), 400
    if "access_token" not in session:
        return jsonify({"error": "unauthorized"}), 401
    data, _ = _gh_get(f"/repos/{repo}/commits/{sha}")
    stats = data.get("stats") or {}; commit = data.get("commit") or {}; author_info = commit.get("author") or {}
    github_author = data.get("author") or {}; github_committer = data.get("committer") or {}
    files_payload = [{
        "filename": f.get("filename"), "status": f.get("status"),
        "additions": f.get("additions"), "deletions": f.get("deletions"),
        "changes": f.get("changes"), "patch": f.get("patch"),
        "blob_url": f.get("blob_url"), "raw_url": f.get("raw_url")
    } for f in data.get("files") or []]
    return jsonify({
        "message": commit.get("message"),
        "author": author_info.get("name"),
        "author_email": author_info.get("email"),
        "author_login": github_author.get("login") or github_committer.get("login"),
        "author_avatar": github_author.get("avatar_url") or github_committer.get("avatar_url"),
        "author_html_url": github_author.get("html_url") or github_committer.get("html_url"),
        "date": author_info.get("date"),
        "stats": {"total": stats.get("total"), "additions": stats.get("additions"), "deletions": stats.get("deletions")},
        "files": files_payload,
        "html_url": data.get("html_url"),
        "verification": commit.get("verification")
    })

@app.get("/api/commit_diff")
def api_commit_diff():
    repo, sha = request.args.get("repo"), request.args.get("sha")
    if not repo or not sha:
        return jsonify({"error": "repo and sha required"}), 400
    if "access_token" not in session:
        return jsonify({"error": "unauthorized"}), 401
    diff_text, _ = _gh_get(f"/repos/{repo}/commits/{sha}", accept_header="application/vnd.github.diff")
    return Response(diff_text, mimetype='text/plain')

@app.get("/api/commit_comments")
def api_commit_comments():
    repo = (request.args.get("repo") or "").strip(); sha = (request.args.get("sha") or "").strip()
    if not repo or not sha:
        return jsonify({"error": "repo and sha required"}), 400
    if "access_token" not in session:
        return jsonify({"error": "unauthorized"}), 401
    try:
        comments, _ = _gh_get(f"/repos/{repo}/commits/{sha}/comments", params={"per_page": 100})
    except requests.exceptions.HTTPError as exc:
        return jsonify({"error": "failed to load comments"}), exc.response.status_code if exc.response else 502
    except requests.exceptions.RequestException:
        return jsonify({"error": "failed to load comments"}), 502
    return jsonify({"comments": [_normalize_commit_comment(c) for c in (comments or [])]})

@app.post("/api/commit_comments")
def api_create_commit_comment():
    if "access_token" not in session:
        return jsonify({"error": "unauthorized"}), 401
    payload = request.get_json(silent=True) or {}
    repo = (payload.get("repo") or "").strip(); sha = (payload.get("sha") or "").strip(); body = (payload.get("body") or "").strip()
    if not repo or not sha or not body:
        return jsonify({"error": "repo, sha, and body are required"}), 400
    comment_payload = {"body": body}; path = (payload.get("path") or "").strip(); side = (payload.get("side") or "RIGHT").upper()
    if path:
        comment_payload["path"] = path
    if payload.get("position") is not None:
        try:
            comment_payload["position"] = int(payload.get("position"))
        except (TypeError, ValueError):
            return jsonify({"error": "position must be an integer"}), 400
    if payload.get("line") is not None:
        try:
            comment_payload["line"] = int(payload.get("line"))
        except (TypeError, ValueError):
            return jsonify({"error": "line must be an integer"}), 400
    if ("line" in comment_payload or "position" in comment_payload) and path and side in {"LEFT", "RIGHT"}:
        comment_payload["side"] = side
    try:
        response = requests.post(
            f"{GITHUB_URL_BASE}/repos/{repo}/commits/{sha}/comments",
            headers=_gh_headers(), json=comment_payload, timeout=TIMEOUT
        )
        if response.status_code == 201:
            return jsonify({"comment": _normalize_commit_comment(response.json())}), 201
        if response.status_code == 422:
            return jsonify({"error": "invalid comment location", "details": response.json()}), 422
        response.raise_for_status()
    except requests.exceptions.HTTPError as exc:
        status = exc.response.status_code if exc.response else 502
        details = exc.response.text if exc.response else None
        return jsonify({"error": "failed to create comment", "details": details}), status
    except requests.exceptions.RequestException:
        return jsonify({"error": "failed to create comment"}), 502
    return jsonify({"error": "unexpected response"}), 502

@app.get("/api/repo_contributors")
def api_repo_contributors():
    repo = (request.args.get("repo") or "").strip()
    if not repo:
        return jsonify({"error": "repo required"}), 400
    if "access_token" not in session:
        return jsonify({"error": "unauthorized"}), 401
    try:
        data, _ = _gh_get(f"/repos/{repo}/contributors", params={"per_page": 100, "anon": "false"})
    except requests.exceptions.HTTPError as exc:
        return jsonify({"error": "failed to load contributors"}), exc.response.status_code if exc.response else 502
    except requests.exceptions.RequestException:
        return jsonify({"error": "failed to load contributors"}), 502
    contributors = [{
        "login": item.get("login"), "contributions": item.get("contributions"),
        "avatar_url": item.get("avatar_url"), "html_url": item.get("html_url"),
        "type": item.get("type"), "site_admin": item.get("site_admin")
    } for item in data or [] if isinstance(item, dict)]
    return jsonify({"contributors": contributors})

@app.get("/api/developer_activity")
def api_developer_activity():
    repo = (request.args.get("repo") or "").strip(); login = (request.args.get("login") or "").strip()
    if not repo or not login:
        return jsonify({"error": "repo and login required"}), 400
    if "access_token" not in session:
        return jsonify({"error": "unauthorized"}), 401
    try:
        commits_data, _ = _gh_get(f"/repos/{repo}/commits", params={"author": login, "per_page": 10})
    except requests.exceptions.HTTPError as exc:
        return jsonify({"error": "failed to load commits"}), exc.response.status_code if exc.response else 502
    except requests.exceptions.RequestException:
        return jsonify({"error": "failed to load commits"}), 502

    commit_summaries = []; hotspots_index = {}; identity_snapshot = None
    for commit_entry in commits_data or []:
        sha = (commit_entry or {}).get("sha")
        if not sha:
            continue
        try:
            detail_data, _ = _gh_get(f"/repos/{repo}/commits/{sha}")
        except requests.exceptions.RequestException:
            continue
        commit_info = detail_data.get("commit") or {}; stats = detail_data.get("stats") or {}; author_info = commit_info.get("author") or {}
        file_summaries = []
        for file_info in detail_data.get("files") or []:
            filename = file_info.get("filename")
            additions = file_info.get("additions") or 0
            deletions = file_info.get("deletions") or 0
            change_count = file_info.get("changes") or (additions + deletions)
            file_summaries.append({
                "filename": filename, "status": file_info.get("status"),
                "additions": additions, "deletions": deletions, "changes": change_count
            })
            if filename:
                hotspot = hotspots_index.setdefault(
                    filename, {"filename": filename, "additions": 0, "deletions": 0, "changes": 0, "commits": 0}
                )
                hotspot["additions"] += additions; hotspot["deletions"] += deletions
                hotspot["changes"] += change_count; hotspot["commits"] += 1
        commit_summaries.append({
            "sha": sha, "message": (commit_info.get("message") or "").split("\n")[0],
            "full_message": commit_info.get("message"), "date": author_info.get("date"),
            "html_url": detail_data.get("html_url"),
            "stats": {"total": stats.get("total"), "additions": stats.get("additions"), "deletions": stats.get("deletions")},
            "files": file_summaries
        })
        if identity_snapshot is None:
            identity_snapshot = _evaluate_identity_risk(
                author_info.get("email"), login, detail_data, repo_full_name=repo, current_commit_sha=sha
            )

    hotspots = sorted(
        hotspots_index.values(),
        key=lambda item: (item["changes"], item["additions"] + item["deletions"]),
        reverse=True
    )[:15]

    comments = []
    try:
        comments_data, _ = _gh_get(f"/repos/{repo}/comments", params={"per_page": 100})
    except requests.exceptions.RequestException:
        comments_data = []
    if comments_data:
        login_lower = login.lower()
        for comment in comments_data:
            if ((comment or {}).get("user") or {}).get("login", "").lower() == login_lower:
                comments.append(_normalize_commit_comment(comment))
                if len(comments) >= 30:
                    break

    profile = {"login": login}
    try:
        profile_data, _ = _gh_get(f"/users/{login}")
        if isinstance(profile_data, dict):
            profile.update({k: profile_data.get(k) for k in ["name", "company", "location", "html_url", "avatar_url", "bio", "type"]})
    except requests.exceptions.RequestException:
        pass

    return jsonify({
        "profile": profile,
        "identity": identity_snapshot,
        "recent_commits": commit_summaries,
        "code_hotspots": hotspots,
        "recent_comments": comments
    })

# --- MODIFIED: /api/security_status 함수를 아래 코드로 교체해주세요 ---
@app.get("/api/security_status")
def api_security_status():
    repo = request.args.get("repo")
    commit_sha = request.args.get("commit") or request.args.get("sha")
    branch = request.args.get("branch")
    user_id = session.get("user_login")

    if not repo or not commit_sha or not user_id:
        return jsonify({"error": "repo, commit, and user_id required"}), 400
    if "access_token" not in session:
        return jsonify({"error": "unauthorized"}), 401

    try:
        cached_item = commits_container.read_item(item=commit_sha, partition_key=repo)
        if cached_item and cached_item.get("securityStatus"):
            log.info(f"Cache hit for {commit_sha} in Cosmos DB.")
            return jsonify(cached_item["securityStatus"])
    except exceptions.CosmosResourceNotFoundError:
        log.info(f"Cache miss for {commit_sha}. Performing live analysis.")
    except Exception as e:
        log.warning(f"Cache read error for {commit_sha}, proceeding with live analysis: {e}")

    live_result = None
    commit_data = None
    bricks_features = None
    identity_assessment = {}

    try:
        commit_data, _ = _gh_get(f"/repos/{repo}/commits/{commit_sha}")
        
        author_email = (commit_data.get("commit", {}).get("author") or {}).get("email")
        author_login = (commit_data.get("author") or {}).get("login")
        identity_assessment = _evaluate_identity_risk(author_email, author_login, commit_data, repo_full_name=repo, current_commit_sha=commit_sha)

        params = {"per_page": 100}
        if branch:
            params["ref"] = f"refs/heads/{branch}"
        
        alerts_data, _ = _gh_get(f"/repos/{repo}/code-scanning/alerts", params=params)
        alerts = alerts_data or []
        commit_alerts = [a for a in alerts if (a.get('most_recent_instance') or {}).get('commit_sha') == commit_sha]
        
        enriched_alerts = [
            {
                'number': a.get('number'), 'rule_id': (a.get('rule') or {}).get('id'), 
                'rule_name': (a.get('rule') or {}).get('name'), 'severity': (a.get('rule') or {}).get('severity'),
                'description': ((a.get('most_recent_instance') or {}).get('message') or {}).get('text'),
                'path': ((a.get('most_recent_instance') or {}).get('location') or {}).get('path'),
                'start_line': ((a.get('most_recent_instance') or {}).get('location') or {}).get('start_line'),
                'html_url': a.get('html_url')
            } for a in commit_alerts[:10]
        ]
        
        # --- MODIFIED: CodeQL 상태 및 요약 메시지 로직 개선 ---
        high_alerts = [a for a in commit_alerts if (a.get('rule') or {}).get('severity', '').lower() in {'critical', 'high'}]
        
        if high_alerts:
            defender_status = 'bad'
            summary_message = f"{len(high_alerts)}개의 '높음' 또는 '심각' 수준의 경고가 발견되었습니다."
        elif commit_alerts:
            defender_status = 'warn'
            summary_message = f"{len(commit_alerts)}개의 '중간' 또는 '낮음' 수준의 경고가 발견되었습니다."
        else:
            defender_status = 'good'
            summary_message = "CodeQL 분석을 통과했습니다. 발견된 경고가 없습니다."
            
        defender = {'status': defender_status, 'summary': summary_message, 'alerts': enriched_alerts}
        # --- 수정 끝 ---

        bricks = {'status': 'unknown', 'summary': 'BRICKS 분석 대기 중.', 'details': []}
        bricks_features = _build_iforest_features_from_commit(repo, commit_sha, branch_name=branch, commit_data=commit_data)
        if bricks_features:
            result = _invoke_databricks_model(bricks_features)
            if result is not None:
                bricks = _bricks_postprocess(result)

        live_result = {'defender': defender, 'sentinel': identity_assessment, 'bricks': bricks}
        
        if bricks.get('status') in ['warn', 'bad']:
            reasons = _generate_anomaly_reasons(bricks_features, identity_assessment)
            live_result['bricks']['reasons'] = reasons

    except requests.exceptions.HTTPError as e:
        if e.response and e.response.status_code in [404, 403]:
            live_result = live_result or {'defender': {'status': 'unknown', 'summary': '결과 없음'}, 'sentinel': identity_assessment, 'bricks': {}}
            return jsonify(live_result)
        log.exception(f"HTTP error during live analysis for {repo}@{commit_sha}")
        return jsonify(error="보안 상태 분석 중 오류 발생"), 500
    except Exception as e:
        log.exception(f"Failed to get live security status for {repo}@{commit_sha}")
        return jsonify(error="보안 상태를 불러오지 못했습니다."), 500

    try:
        statuses = [(live_result.get(k) or {}).get('status', 'good') for k in ['defender', 'sentinel', 'bricks']]
        failures = [s for s in statuses if s in ['warn', 'bad']]
        
        if failures and commit_data:
            commit_author_info = commit_data.get("commit", {}).get("author", {})
            commit_date_str = commit_author_info.get("date")
            issue_doc = {
                'id': commit_sha, 'userId': user_id, 'repoFullName': repo,
                'author': commit_author_info.get("name"), 'date': commit_date_str,
                'message': (commit_data.get("commit", {}).get("message") or "").split("\n")[0],
                'failureCount': len(failures), 'securityStatus': live_result
            }
            if commit_date_str:
                issue_doc['yearMonth'] = datetime.fromisoformat(commit_date_str.replace('Z', '+00:00')).strftime('%Y-%m')
            
            issues_container.upsert_item(issue_doc)
            log.info(f"Logged security issue for {commit_sha}.")
            
    except Exception as e:
        log.warning(f"Failed to log security issue for {commit_sha}: {e}")

    try:
        commit_doc_cache = { 'id': commit_sha, 'repoFullName': repo, 'securityStatus': live_result }
        commits_container.upsert_item(commit_doc_cache)
    except Exception as e:
        log.warning(f"Failed to save to commits cache for {commit_sha}: {e}")

    return jsonify(live_result)

# ---------- 에러 핸들러 및 실행 ----------
@app.errorhandler(PermissionError)
def _unauth(_):
    session.clear()
    if request.path.startswith("/api/"):
        return jsonify({"error": "unauthorized"}), 401
    return redirect(url_for("index"))

@app.errorhandler(Exception)
def handle_exception(e):
    if hasattr(e, 'code') and isinstance(e.code, int) and 400 <= e.code < 600:
        return e
    log.exception("An unhandled exception occurred")
    return jsonify(error="Internal server error"), 500

@app.route("/issues")
def issues():
    if "access_token" not in session:
        return redirect(url_for("index"))
    return render_template("issues_dashboard.html", user_id=session.get("user_login") or "me")

@app.get("/api/issues")
def api_issues():
    if "access_token" not in session:
        return jsonify({"error": "unauthorized"}), 401
    
    user_id = session.get("user_login")
    if not user_id:
        return jsonify({"error": "user not found in session"}), 401

    log.info(f"Fetching security issues for {user_id} from Cosmos DB")
    try:
        query = "SELECT * FROM c WHERE c.userId = @userId ORDER BY c.date DESC"
        params = [{"name": "@userId", "value": user_id}]
        
        issues_list = list(issues_container.query_items(
            query=query, parameters=params, enable_cross_partition_query=False
        ))
        return jsonify(issues_list)
        
    except Exception as e:
        log.exception(f"Failed to get issues from Cosmos DB for {user_id}")
        return jsonify({"error": f"Failed to fetch issues from Cosmos DB: {str(e)}"}), 500

if __name__ == "__main__":
    debug_mode = os.environ.get("FLASK_DEBUG", "").lower() in {"1", "true", "yes"}
    port = int(os.environ.get("PORT", "8000"))
    app.run(host="0.0.0.0", port=port, debug=debug_mode)