# NEW: eventlet을 가장 먼저 import하고 monkey_patch를 실행해야 합니다.
import eventlet
eventlet.monkey_patch()

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
from flask_socketio import SocketIO
from azure.cosmos import CosmosClient, PartitionKey, exceptions

import requests
from flask import (
    Flask, render_template, request, redirect, session,
    url_for, jsonify, Response
)
# NEW: Flask-SocketIO 라이브러리를 임포트합니다.
from flask_socketio import SocketIO

from azure.cosmos import CosmosClient, PartitionKey, exceptions

azure_logger = logging.getLogger('azure')
azure_logger.setLevel(logging.DEBUG)

# ---------- 기본 설정 ----------
COMMITS_PER_BRANCH = 5

COSMOS_CONNECTION_STRING = os.environ.get("COSMOS_DB_CONNECTION_STRING")
COSMOS_DATABASE_NAME = "ProjectGuardianDB"
COSMOS_REPOS_CONTAINER = "repositories"
COSMOS_COMMITS_CONTAINER = "commits"
COSMOS_ISSUES_CONTAINER = "security_issues"

cosmos_client = CosmosClient.from_connection_string(COSMOS_CONNECTION_STRING)
database_client = cosmos_client.get_database_client(COSMOS_DATABASE_NAME)
repos_container = database_client.get_container_client(COSMOS_REPOS_CONTAINER)
commits_container = database_client.get_container_client(COSMOS_COMMITS_CONTAINER)
issues_container = database_client.get_container_client(COSMOS_ISSUES_CONTAINER)

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("web.app")

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev-secret")

# NEW: SocketIO를 초기화합니다.
# async_mode='eventlet'은 프로덕션 환경에서 권장되는 비동기 서버입니다.
# cors_allowed_origins="*"는 모든 출처에서의 웹소켓 연결을 허용합니다.
socketio = SocketIO(app, async_mode='eventlet', cors_allowed_origins="*")


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

GITHUB_URL_BASE = "https://api.github.com"
GITHUB_URL_USER = f"{GITHUB_URL_BASE}/user"
GITHUB_URL_REPOS = f"{GITHUB_URL_BASE}/user/repos"
GITHUB_URL_REPO_COMMITS = f"{GITHUB_URL_BASE}/repos/{{repo}}/commits"
GITHUB_URL_REPO_BRANCHES = f"{GITHUB_URL_BASE}/repos/{{repo}}/branches"

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

def _generate_anomaly_reasons(features, sentinel_status):
    reasons = []
    if not features:
        return reasons

    hour = features.get("hour")
    is_mainline = features.get("ref_is_mainline", 0) > 0
    is_sensitive = features.get("is_sensitive_type", 0) > 0
    is_dependency = features.get("is_dependency_change", 0) > 0
    push_size = features.get("push_size", 0)
    push_distinct = features.get("push_distinct", 0)
    repo_push_q90 = features.get("repo_push_q90", 0.0)
    is_first_contrib = sentinel_status and sentinel_status.get("first_contribution")

    if is_sensitive and is_mainline:
        reasons.append("민감한 키워드가 포함된 파일을 주요 브랜치(main/master)에 직접 수정했습니다.")
    elif is_sensitive:
        reasons.append("민감한 키워드(secret, key 등)가 포함된 파일을 수정했습니다.")

    if is_dependency and is_mainline:
        reasons.append("의존성 관리 파일을 주요 브랜치에 직접 수정했습니다.")
    elif is_dependency:
        reasons.append("프로젝트 의존성(라이브러리 등) 관련 파일을 수정했습니다.")

    if hour is not None and (1 <= hour <= 5):
        reasons.append(f"일반적이지 않은 시간(새벽 {hour}시)에 커밋이 발생했습니다.")

    if repo_push_q90 > 100 and push_size > repo_push_q90 * 1.5:
        reasons.append(f"평소보다 많은 양의 코드({int(push_size)}줄)를 한 번에 커밋했습니다. (평균 {int(repo_push_q90)}줄)")
    elif push_size > 1000:
        reasons.append(f"코드 변경량이 {int(push_size)}줄로 매우 많습니다.")
        
    if push_distinct > 20:
        reasons.append(f"{int(push_distinct)}개의 많은 파일을 한 번에 수정했습니다.")

    if is_first_contrib:
        reasons.append("이 저장소에 처음으로 기여한 사용자의 커밋입니다.")
        
    if features.get("actor_hour_ratio", 0.0) > 0.7 and features.get("actor_hour_events", 0) > 5:
        reasons.append("최근 1시간 이내에 활동이 집중적으로 발생했습니다.")

    if not reasons:
        reasons.append("여러 요인(시간, 변경량, 파일 유형 등)을 복합적으로 분석한 결과 '주의' 상태로 판단되었습니다.")

    return list(dict.fromkeys(reasons))

def _get_code_excerpt(repo_full_name, ref, path, start_line, end_line):
    if not path or not start_line: return []
    try:
        file_data, _ = _gh_get(f"/repos/{repo_full_name}/contents/{path}", params={"ref": ref})
        if not isinstance(file_data, dict) or file_data.get('encoding') != 'base64' or not file_data.get('content'): return []
        decoded = base64.b64decode(file_data['content']).decode('utf-8', errors='replace')
        lines = decoded.splitlines()
        if not lines: return []
        total_lines = len(lines)
        end_line = end_line or start_line
        start, end = max(1, start_line - 2), min(total_lines, end_line + 2)
        return [{'line': lineno, 'content': lines[lineno - 1] if 0 <= lineno - 1 < total_lines else '', 'highlight': start_line <= lineno <= end_line} for lineno in range(start, end + 1)]
    except Exception:
        return []

# ---------- Databricks 모델 통합 ----------
def _safe_parse_iso8601(value):
    if not value: return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None

def _count_sensitive_paths(files):
    return sum(1 for f in files or [] if any(k in (f.get("filename") or "").lower() for k in SENSITIVE_KEYWORDS))

def _count_dependency_changes(files):
    total = 0
    for file_info in files or []:
        name = (file_info.get("filename") or "").lower()
        if not name: continue
        if any(name.endswith(sfx) for sfx in DEPENDENCY_FILE_SUFFIXES) or any(name == m or name.endswith(f"/{m}") for m in DEPENDENCY_FILE_MATCHES):
            total += 1
    return total

def _is_first_contribution(repo_full_name, author_login=None, current_commit_sha=None):
    if not all([repo_full_name, author_login, current_commit_sha]): return None
    try:
        commits, _ = _gh_get(f"/repos/{repo_full_name}/commits", params={"author": author_login, "per_page": 2})
        shas = [c.get("sha", "").lower() for c in (commits or []) if c]
        return len(shas) == 1 and (current_commit_sha or "").lower() in shas
    except requests.exceptions.RequestException:
        return None

def _normalize_commit_comment(comment):
    if not isinstance(comment, dict): return {}
    user = comment.get("user") or {}
    return {
        "id": comment.get("id"), "path": comment.get("path"), "line": comment.get("line"),
        "position": comment.get("position"), "commit_id": comment.get("commit_id"),
        "created_at": comment.get("created_at"), "updated_at": comment.get("updated_at"),
        "body": comment.get("body"), "html_url": comment.get("html_url") or comment.get("url"),
        "author_association": comment.get("author_association"),
        "user": {"login": user.get("login"), "html_url": user.get("html_url"), "avatar_url": user.get("avatar_url"), "type": user.get("type")},
        "in_reply_to_id": comment.get("in_reply_to_id"), "side": comment.get("side"),
    }

def _fetch_event_stats(repo_full_name, actor_login):
    if not repo_full_name or not actor_login: return {}
    owner, repo_name = repo_full_name.split('/')
    one_hour_ago = datetime.now(timezone.utc) - timedelta(hours=1)
    try:
        user_events, _ = _gh_get(f"/users/{actor_login}/events/public", params={"per_page": 100})
        repo_events, _ = _gh_get(f"/repos/{owner}/{repo_name}/events", params={"per_page": 100})
        actor_hour_events = sum(1 for e in user_events or [] if _safe_parse_iso8601(e.get("created_at")) > one_hour_ago)
        actor_repo_events = sum(1 for e in user_events or [] if (e.get("repo") or {}).get("name") == repo_full_name)
        push_sizes = [e.get("payload", {}).get("size", 0) for e in repo_events or [] if e.get("type") == "PushEvent"]
        repo_push_q90 = sorted(push_sizes)[int(len(push_sizes) * 0.9)] if push_sizes else 0.0
        return {
            "actor_events_total": len(user_events or []), "repo_events_total": len(repo_events or []),
            "actor_repo_events": actor_repo_events, "actor_hour_events": actor_hour_events,
            "actor_hour_ratio": actor_hour_events / len(user_events or []) if user_events else 0.0,
            "repo_push_q90": float(repo_push_q90), "org_events_total": 0, "actor_org_events": 0,
        }
    except Exception:
        return {}

def _build_iforest_features_from_commit(repo_full_name, commit_sha, branch_name=None, commit_data=None, hint=None):
    if not repo_full_name or not commit_sha: return None
    try:
        commit_data = commit_data or _gh_get(f"/repos/{repo_full_name}/commits/{commit_sha}")[0]
    except Exception:
        return None
    commit_info = commit_data.get("commit", {})
    author_info = commit_info.get("author", {})
    commit_files = commit_data.get("files", [])
    stats = commit_data.get("stats", {})
    dt_utc = _safe_parse_iso8601(author_info.get("date"))
    kst_tz = timezone(timedelta(hours=9))
    dt_kst = dt_utc.astimezone(kst_tz) if dt_utc else None
    author_login = (commit_data.get("author") or {}).get("login")
    event_stats = _fetch_event_stats(repo_full_name, author_login)
    return {
        "type": (hint or {}).get("event_type", "PushEvent"),
        "created_at_ts": int(dt_utc.timestamp()) if dt_utc else 0,
        "hour": dt_kst.hour if dt_kst else 0,
        "push_size": float(stats.get("total", 0)),
        "push_distinct": float(len(commit_files)),
        "ref_is_mainline": 1.0 if branch_name and branch_name.lower() in {'main', 'master'} else 0.0,
        "is_sensitive_type": 1.0 if _count_sensitive_paths(commit_files) > 0 else 0.0,
        "is_dependency_change": 1.0 if _count_dependency_changes(commit_files) > 0 else 0.0,
        **event_stats
    }

def _extract_anomaly_details(response_json):
    def _coerce_bool(v):
        return v if isinstance(v, bool) else str(v).lower() in {"1", "true", "t", "yes", "y"}
    cand = response_json
    if isinstance(cand, dict):
        for key in ("predictions", "outputs", "data"):
            if key in cand:
                arr = cand.get(key)
                cand = arr[0] if isinstance(arr, list) and arr else arr
                break
    if isinstance(cand, (int, float)): return {"score": float(cand), "is_anomaly": None, "threshold": None}
    if not isinstance(cand, dict): return None
    score = next((float(cand[k]) for k in ("anomaly_score", "score") if k in cand and isinstance(cand[k], (int, float))), None)
    is_anom = next((_coerce_bool(cand[k]) for k in ("is_anomaly", "is_outlier") if k in cand), None)
    threshold = next((float(cand[k]) for k in ("threshold_used", "threshold") if k in cand and isinstance(cand[k], (int, float))), None)
    if score is not None and is_anom is None and threshold is not None:
        is_anom = score >= threshold
    return {"score": score, "is_anomaly": is_anom, "threshold": threshold} if score is not None and is_anom is not None else None

def _bricks_postprocess(model_parsed: dict):
    score, is_anom, threshold = model_parsed.get('score'), model_parsed.get('is_anomaly'), model_parsed.get('threshold')
    if is_anom:
        status = 'bad'
    elif threshold is not None and score >= 0.9 * threshold:
        status = 'warn'
    else:
        status = 'good'
    summary = ('임계값 초과 (이상치)' if is_anom else ('임계값 근접 (주의)' if status == 'warn' else '정상 범위'))
    return {'status': status, 'summary': summary, **model_parsed}

def _invoke_databricks_model(features):
    if not all([features, DATABRICKS_ENDPOINT, DATABRICKS_TOKEN]): return None
    model_features = features.copy()
    model_features.pop('is_dependency_change', None)
    headers = {"Authorization": f"Bearer {DATABRICKS_TOKEN}", "Content-Type": "application/json"}
    payload = {"dataframe_records": [model_features]}
    try:
        response = requests.post(DATABRICKS_ENDPOINT, headers=headers, json=payload, timeout=DATABRICKS_TIMEOUT)
        response.raise_for_status()
        result_json = response.json()
        log.info(f"✅ Databricks response: {result_json}")
        ext = _extract_anomaly_details(result_json)
        return ext if ext else None
    except requests.RequestException:
        return None

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
        details = [f"확인된 표시 이름: {display_name}", f"이메일: {email}", "사용자 유형: Member"]
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

@app.route("/")
def index():
    return redirect(url_for("dashboard")) if "access_token" in session else render_template("index.html")

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
    if not code: return "Missing code", 400
    res = requests.post("https://github.com/login/oauth/access_token", data={"client_id": GITHUB_CLIENT_ID, "client_secret": GITHUB_CLIENT_SECRET, "code": code}, headers={"Accept": "application/json"}, timeout=TIMEOUT)
    res.raise_for_status()
    session["access_token"] = res.json().get("access_token")
    me, _ = _gh_get("/user")
    session["user_login"] = me.get("login", "")
    return redirect(url_for("loading"))

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))

@app.route("/dashboard")
def dashboard():
    if "access_token" not in session: return redirect(url_for("index"))
    return render_template("dashboard_branch.html", user_id=session.get("user_login", "me"))

@app.route("/details")
def details():
    if "access_token" not in session: return redirect(url_for("index"))
    repo, sha, branch = request.args.get("repo"), request.args.get("sha"), request.args.get("branch")
    if not repo or not sha: return "리포지토리와 커밋 SHA가 필요합니다.", 400
    return render_template("detail_view.html", user_id=session.get("user_login", "me"), repo_name=repo, commit_sha=sha, branch_name=branch)

# ---------- API ----------
@app.get("/api/healthz")
def healthz():
    return jsonify({"ok": True, "time": datetime.utcnow().isoformat() + "Z"})

@socketio.on('connect')
def handle_connect():
    log.info(f"Client connected: {request.sid}")

@socketio.on('disconnect')
def handle_disconnect():
    log.info(f"Client disconnected: {request.sid}")

# NEW: 웹훅 알림을 수신하고 클라이언트에 전파하는 API
@app.route('/api/webhook_notify', methods=['POST'])
def webhook_notify():
    data = request.json
    repo_full_name = data.get('repoFullName')
    if not repo_full_name:
        return jsonify(error="repoFullName is required"), 400
    
    log.info(f"Received update notification for repo: {repo_full_name}")
    # 'repo_updated' 이벤트를 모든 연결된 클라이언트에게 전송 (broadcast)
    socketio.emit('repo_updated', {'repoFullName': repo_full_name})
    
    return jsonify(status="notification sent"), 200

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
        
        sanitized_repo_id = repo_full_name.replace('/', '-')
            
        if not full_sync:
            try:
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

            repo_doc = {
                'id': sanitized_repo_id,
                'repoFullName': repo_full_name,
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
                    {"name": "@repo", "value": repo_name_original},
                    {"name": "@branch", "value": branch_name}
                ]
                
                branch_commits = list(commits_container.query_items(query=commit_query, parameters=commit_params))
                key = f"{repo_name_original}|{branch_name}"
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

    commits_data, _ = _gh_get(f"/repos/{repo}/commits", params={
        "sha": branch, "per_page": per_page, "page": page
    })
    
    commit_list = (commits_data or [])
    commit_shas = [c.get("sha") for c in commit_list if c.get("sha")]

    security_statuses = {}
    if commit_shas:
        try:
            query = f"SELECT c.id, c.securityStatus FROM c WHERE c.repoFullName = @repo AND c.id IN ({', '.join([f'@sha{i}' for i in range(len(commit_shas))])})"
            params = [{"name": "@repo", "value": repo}]
            for i, sha in enumerate(commit_shas):
                params.append({"name": f"@sha{i}", "value": sha})
            
            results = commits_container.query_items(query=query, parameters=params, partition_key=repo)
            for item in results:
                security_statuses[item['id']] = item.get('securityStatus')
        except Exception as e:
            log.warning(f"Could not bulk fetch security statuses from Cosmos DB: {e}")

    commits_with_status = []
    for c in commit_list:
        sha = c.get("sha")
        commit_info = {
            "sha": sha,
            "message": (c.get("commit", {}).get("message") or "").split("\n")[0],
            "author": (c.get("commit", {}).get("author") or {}).get("name"),
            "date": (c.get("commit", {}).get("author") or {}).get("date"),
            "securityStatus": security_statuses.get(sha)
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

@app.get("/api/security_status")
def api_security_status():
    repo = request.args.get("repo")
    commit_sha = request.args.get("commit") or request.args.get("sha")
    branch = request.args.get("branch")
    user_id = session.get("user_login")
    force_refresh = request.args.get("force_refresh", "false").lower() == "true"

    if not repo or not commit_sha or not user_id:
        return jsonify({"error": "repo, commit, and user_id required"}), 400
    if "access_token" not in session:
        return jsonify({"error": "unauthorized"}), 401

    if not force_refresh:
        try:
            cached_item = commits_container.read_item(item=commit_sha, partition_key=repo)
            if cached_item and cached_item.get("securityStatus"):
                log.info(f"Cache hit for {commit_sha} in Cosmos DB.")
                return jsonify(cached_item["securityStatus"])
        except exceptions.CosmosResourceNotFoundError:
            log.info(f"Cache miss for {commit_sha}. Performing live analysis.")
        except Exception as e:
            log.warning(f"Cache read error for {commit_sha}, proceeding with live analysis: {e}")
    else:
        log.info(f"Force refresh requested for {commit_sha}. Performing live analysis.")


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
        log.info(f"Upserted security status for {commit_sha} to cache.")
        
    except Exception as e:
        log.warning(f"Failed to save to commits cache for {commit_sha}: {e}")
    except requests.exceptions.HTTPError as e:
        if e.response and e.response.status_code in [404, 403]:
            live_result = live_result or {'defender': {'status': 'unknown', 'summary': '결과 없음'}, 'sentinel': identity_assessment, 'bricks': {}}
            return jsonify(live_result)
        log.exception(f"HTTP error during live analysis for {repo}@{commit_sha}")
        error_details = f"HTTP 분석 오류: {str(e)}"
        return jsonify(error=error_details), 500
    except Exception as e:
        log.exception(f"Failed to get live security status for {repo}@{commit_sha}")
        error_details = f"내부 서버 오류: {str(e)}"
        return jsonify(error=error_details), 500

    return jsonify(live_result)


# ---------- 에러 핸들러 및 실행 ----------
@app.errorhandler(PermissionError)
def _unauth(_):
    session.clear()
    return jsonify({"error": "unauthorized"}), 401 if request.path.startswith("/api/") else redirect(url_for("index"))

@app.errorhandler(Exception)
def handle_exception(e):
    if hasattr(e, 'code') and isinstance(e.code, int) and 400 <= e.code < 600: return e
    log.exception("An unhandled exception occurred")
    return jsonify(error="Internal server error"), 500

@app.route("/issues")
def issues():
    if "access_token" not in session: return redirect(url_for("index"))
    return render_template("issues_dashboard.html", user_id=session.get("user_login", "me"))

@app.get("/api/issues")
def api_issues():
    if "access_token" not in session: return jsonify({"error": "unauthorized"}), 401
    user_id = session.get("user_login")
    if not user_id: return jsonify({"error": "user not found in session"}), 401
    try:
        query = "SELECT * FROM c WHERE c.userId = @userId ORDER BY c.date DESC"
        params = [{"name": "@userId", "value": user_id}]
        issues_list = list(issues_container.query_items(query=query, parameters=params))
        return jsonify(issues_list)
    except Exception as e:
        log.exception(f"Failed to get issues from Cosmos DB for {user_id}")
        return jsonify({"error": str(e)}), 500

# MODIFIED: 앱 실행 방식을 socketio.run으로 변경
if __name__ == "__main__":
    debug_mode = os.environ.get("FLASK_DEBUG", "false").lower() in {"1", "true", "yes"}
    port = int(os.environ.get("PORT", "8000"))
    # Gunicorn이 아닌, 직접 python app.py로 실행할 때를 위한 부분입니다.
    socketio.run(app, host="0.0.0.0", port=port, debug=debug_mode)