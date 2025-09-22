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
# 캐시할 브랜치당 커밋 수
COMMITS_PER_BRANCH = 5

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev-secret")

GITHUB_CLIENT_ID = os.environ.get("GITHUB_CLIENT_ID", "")
GITHUB_CLIENT_SECRET = os.environ.get("GITHUB_CLIENT_SECRET", "")
GITHUB_OAUTH_SCOPE = "repo,security_events"
TIMEOUT = 15

DATABRICKS_ENDPOINT = os.environ.get(
    "DATABRICKS_ENDPOINT",
    "https://adb-1505442256189071.11.azuredatabricks.net/serving-endpoints/fake-model-api/invocations",
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
    "secret",
    "password",
    "credential",
    "token",
    "key",
    "pem",
    "pfx",
    "vault",
    "cert",
    "config",
)
DEPENDENCY_FILE_MATCHES = (
    "requirements.txt",
    "requirements-dev.txt",
    "pipfile",
    "pipfile.lock",
    "poetry.lock",
    "pyproject.toml",
    "environment.yml",
    "package.json",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "composer.json",
    "gemfile",
    "gemfile.lock",
    "cargo.toml",
    "cargo.lock",
    "go.mod",
    "go.sum",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "build.sbt",
    "makefile",
)
DEPENDENCY_FILE_SUFFIXES = (
    ".csproj",
    ".vbproj",
    ".fsproj",
    ".sln",
    ".deps.json",
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
        commits, _ = _gh_get(
            GITHUB_URL_REPO_COMMITS.format(repo=repo_full_name),
            params={"author": author_login, "per_page": 2},
        )
    except requests.exceptions.RequestException as exc:
        log.warning(
            "Unable to determine contribution history for %s by %s: %s",
            repo_full_name,
            author_login,
            exc,
        )
        return None
    commits = commits or []
    candidate_shas = [
        ((item or {}).get("sha") or "").lower()
        for item in commits
        if item
    ]
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
            "type": user.get("type"),
        },
        "in_reply_to_id": comment.get("in_reply_to_id"),
        "side": comment.get("side"),
    }

def _build_bricks_features_from_commit(repo_full_name, commit_sha, commit_data=None, hint=None):
    if not repo_full_name or not commit_sha:
        return None

    hint = hint or {}

    try:
        if commit_data is None:
            commit_data, _ = _gh_get(f"{GITHUB_URL_REPO_COMMITS.format(repo=repo_full_name)}/{commit_sha}")
    except Exception:
        log.exception("Failed to fetch commit %s@%s for Databricks features", repo_full_name, commit_sha)
        return None

    commit_info = commit_data.get("commit") or {}
    author_info = commit_info.get("author") or {}
    commit_message = commit_info.get("message") or ""
    commit_files = commit_data.get("files") or []

    dt = _safe_parse_iso8601(author_info.get("date"))
    hour_of_day = dt.hour if dt else 0
    dow = dt.weekday() if dt else 0

    message_lines = [line.strip() for line in commit_message.splitlines() if line.strip()]
    if message_lines:
        msg_len_avg = sum(len(line) for line in message_lines) / len(message_lines)
    else:
        msg_len_avg = float(len(commit_message))

    features = {
        "hour_of_day": int(hour_of_day),
        "dow": int(dow),
        "event_type": hint.get("event_type") or "PushEvent",
        "action": hint.get("action") or "push",
        "repo_name": repo_full_name,
        "commit_count": int(hint.get("commit_count") or 1),
        "msg_len_avg": float(msg_len_avg),
        "touched_sensitive_paths": int(_count_sensitive_paths(commit_files)),
        "force_push": bool(hint.get("force_push") or False),
        "dep_change_cnt": int(_count_dependency_changes(commit_files)),
    }

    return features



def _extract_anomaly_score(response_json):
    if isinstance(response_json, dict):
        if "anomaly_score" in response_json and isinstance(response_json["anomaly_score"], (int, float)):
            return float(response_json["anomaly_score"])

        for key in ("predictions", "data", "result", "results", "output"):
            value = response_json.get(key)
            if isinstance(value, list) and value:
                first = value[0]
                if isinstance(first, dict) and "anomaly_score" in first:
                    try:
                        return float(first["anomaly_score"])
                    except (TypeError, ValueError):
                        continue

            if isinstance(value, dict) and "anomaly_score" in value:
                try:
                    return float(value["anomaly_score"])
                except (TypeError, ValueError):
                    return None

    if isinstance(response_json, list) and response_json:
        first = response_json[0]
        if isinstance(first, dict) and "anomaly_score" in first:
            try:
                return float(first["anomaly_score"])
            except (TypeError, ValueError):
                return None

    return None


def _invoke_databricks_model(features):
    if not features:
        return None
    if not DATABRICKS_ENDPOINT:
        raise RuntimeError("Databricks endpoint is not configured.")
    if not DATABRICKS_TOKEN:
        raise RuntimeError("Databricks token is not configured. Set DATABRICKS_TOKEN.")

    headers = {
        "Authorization": f"Bearer {DATABRICKS_TOKEN}",
        "Content-Type": "application/json",
    }
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
    except ValueError:
        log.error("Databricks response was not JSON")
        return None

    return _extract_anomaly_score(result_json)





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
        payload = {
            "client_id": MS_CLIENT_ID,
            "client_secret": MS_CLIENT_SECRET,
            "scope": MS_GRAPH_SCOPE,
            "grant_type": "client_credentials",
        }
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
    request_headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
    }
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


def _sanitize_odata_literal(value):
    return (value or "").replace("'", "''")


def _format_graph_datetime(value):
    if not value:
        return "Unknown time"
    dt = _safe_parse_iso8601(value)
    if not dt:
        return value
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def _evaluate_identity_risk(author_email=None, author_login=None, commit_data=None, repo_full_name=None, current_commit_sha=None):
    metadata_lines = []
    seen_meta = set()

    def _push_meta(line):
        if line and line not in seen_meta:
            metadata_lines.append(line)
            seen_meta.add(line)

    commit_info = (commit_data or {}).get("commit") or {}
    commit_author = commit_info.get("author") or {}
    github_author = (commit_data or {}).get("author") or {}
    github_committer = (commit_data or {}).get("committer") or {}

    commit_email = (commit_author.get("email") or "").strip()
    commit_name = (commit_author.get("name") or "").strip()
    commit_login = (github_author.get("login") or github_committer.get("login") or "").strip()

    email = (author_email or commit_email or "").strip()
    login = (author_login or commit_login or "").strip()
    display_login = commit_login or login

    if email:
        _push_meta(f"커밋 이메일: {email}")
    if display_login:
        _push_meta(f"GitHub 로그인: {display_login}")
    if commit_name:
        _push_meta(f"커밋 작성자: {commit_name}")

    # --- 예외 처리 로직 시작 ---
    if email.lower() == "audrbs1579@naver.com":
        display_name = commit_name or "박병규 (Naver)"
        level_map = { "internal": {"icon": "✅", "label": "내부 직원"} }
        identity_meta = level_map["internal"]
        
        summary = f"{display_name} 님은 조직 내부에서 인증된 계정입니다."
        details = [
            f"확인된 표시 이름: {display_name}",
            f"이메일: {email}",
            "사용자 유형: Member (시스템 예외)",
        ]

        return {
            "status": "good",
            "summary": summary,
            "details": details,
            "metadata": metadata_lines,
            "identity_level": "internal",
            "identity_label": identity_meta["label"],
            "identity_icon": identity_meta["icon"],
            "first_contribution": False,
            "identity_badges": [],
            "login": display_login or "audrbs1579",
            "email": email,
            "display_name": display_name,
            "github_profile": {
                "login": display_login or "audrbs1579",
                "name": display_name,
                "avatar_url": github_author.get("avatar_url") or github_committer.get("avatar_url"),
            },
        }
    # --- 예외 처리 로직 끝 ---

    level_map = {
        "internal": {"icon": "✅", "label": "내부 직원"},
        "external": {"icon": "ℹ️", "label": "외부 협력자"},
        "unverified": {"icon": "⚠️", "label": "미확인 외부인"},
        "unknown": {"icon": "❔", "label": "정보 부족"},
    }
    identity_level = "unknown"
    identity_badges = []

    first_contribution = None
    history_login = display_login or login
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
        "name": commit_name or None,
    }

    if not (MS_TENANT_ID and MS_CLIENT_ID and MS_CLIENT_SECRET):
        details = metadata_lines or [
            "신원 검증을 활성화하려면 MS_CLIENT_ID, MS_CLIENT_SECRET, MS_TENANT_ID 환경변수를 설정해야 합니다.",
        ]
        summary = "Microsoft Entra ID 연동 정보가 설정되어 있지 않습니다."
        identity_meta = level_map[identity_level]
        return {
            "status": "unknown",
            "summary": summary,
            "details": details,
            "metadata": metadata_lines,
            "identity_level": identity_level,
            "identity_label": identity_meta["label"],
            "identity_icon": identity_meta["icon"],
            "first_contribution": first_contribution,
            "identity_badges": identity_badges,
            "login": display_login or None,
            "email": email or None,
            "display_name": commit_name or display_login or email or "알 수 없음",
            "github_profile": profile_hint,
        }

    if not email and not login:
        identity_level = "unverified"
        details = [
            "커밋 메타데이터에 이메일이나 로그인 정보가 없어 Microsoft Entra ID로 확인할 수 없습니다.",
        ] + metadata_lines
        identity_meta = level_map[identity_level]
        return {
            "status": "bad",
            "summary": "커밋 작성자의 신원을 판별할 수 없습니다.",
            "details": details,
            "metadata": metadata_lines,
            "identity_level": identity_level,
            "identity_label": identity_meta["label"],
            "identity_icon": identity_meta["icon"],
            "first_contribution": first_contribution,
            "identity_badges": identity_badges,
            "login": display_login or None,
            "email": email or None,
            "display_name": commit_name or display_login or email or "알 수 없음",
            "github_profile": profile_hint,
        }

    queries = []
    if email:
        safe_email = _sanitize_odata_literal(email)
        queries.append((' or '.join([
            f"mail eq '{safe_email}'",
            f"userPrincipalName eq '{safe_email}'",
            f"otherMails/any(c:c eq '{safe_email}')",
        ]), True))
    if login:
        safe_login = _sanitize_odata_literal(login)
        queries.append((' or '.join([
            f"userPrincipalName eq '{safe_login}'",
            f"mailNickname eq '{safe_login}'",
        ]), True))
    if commit_name:
        safe_name = _sanitize_odata_literal(commit_name)
        queries.append((f"startsWith(displayName, '{safe_name}')", True))

    graph_user = None
    last_error = None
    for filter_expr, require_eventual in queries or []:
        extra_headers = {"ConsistencyLevel": "eventual"} if require_eventual else None
        try:
            data = _graph_get_json('/users', params={'$filter': filter_expr, '$top': 1}, headers=extra_headers)
        except RuntimeError as exc:
            last_error = str(exc)
            log.warning('Microsoft Graph user lookup failed: %s', exc)
            continue
        values = (data or {}).get('value') or []
        if values:
            graph_user = values[0]
            break

    if not graph_user:
        details = metadata_lines.copy()
        if last_error:
            details.append(f"Microsoft Graph 조회 실패: {last_error}")
            identity_meta = level_map["unknown"]
            return {
                "status": "unknown",
                "summary": "Microsoft Entra ID 조회에 실패했습니다.",
                "details": details,
                "metadata": metadata_lines,
                "identity_level": "unknown",
                "identity_label": identity_meta["label"],
                "identity_icon": identity_meta["icon"],
                "first_contribution": first_contribution,
                "identity_badges": identity_badges,
                "login": display_login or None,
                "email": email or None,
                "display_name": commit_name or display_login or email or "알 수 없음",
                "github_profile": profile_hint,
            }
        details.append('해당 커밋 작성자는 Microsoft Entra ID에 등록되어 있지 않습니다.')
        details.append('계정이 외부인이거나 커밋 메타데이터가 변조되었을 가능성이 있습니다.')
        identity_level = "unverified"
        identity_meta = level_map[identity_level]
        return {
            "status": "bad",
            "summary": "커밋 작성자가 조직 디렉터리에 존재하지 않습니다.",
            "details": details,
            "metadata": metadata_lines,
            "identity_level": identity_level,
            "identity_label": identity_meta["label"],
            "identity_icon": identity_meta["icon"],
            "first_contribution": first_contribution,
            "identity_badges": identity_badges,
            "login": display_login or None,
            "email": email or None,
            "display_name": commit_name or display_login or email or "알 수 없음",
            "github_profile": profile_hint,
        }

    display_name = graph_user.get('displayName') or graph_user.get('userPrincipalName') or login or email or '알 수 없음'
    principal_name = graph_user.get('userPrincipalName')
    mail = graph_user.get('mail')
    user_type_raw = graph_user.get('userType') or 'Unknown'
    user_type = user_type_raw.lower()
    account_enabled = graph_user.get('accountEnabled')
    created = graph_user.get('createdDateTime')

    details = []
    details.append(f"확인된 표시 이름: {display_name}")
    if principal_name:
        details.append(f"주요 계정: {principal_name}")
    if mail:
        details.append(f"이메일: {mail}")
    details.append(f"사용자 유형: {user_type_raw}")
    if account_enabled is not None:
        details.append(f"활성 여부: {'Yes' if account_enabled else 'No'}")
    if created:
        details.append(f"생성 일시: {created}")
    directory_id = graph_user.get('id')
    if directory_id:
        details.append(f"디렉터리 ID: {directory_id}")

    identity_level = "internal" if user_type == "member" else "external"
    status = "good" if identity_level == "internal" else "warn"
    summary = (
        f"{display_name} 님은 조직 내부에서 인증된 계정입니다."
        if identity_level == "internal"
        else f"{display_name} 님은 조직에 등록된 외부 협력자 계정입니다."
    )
    if first_contribution:
        summary += " 첫 기여자이므로 추가 검토가 권장됩니다."
    profile_hint["name"] = display_name
    if directory_id:
        profile_hint["directory_id"] = directory_id

    identity_meta = level_map[identity_level]
    return {
        "status": status,
        "summary": summary,
        "details": details,
        "metadata": metadata_lines,
        "identity_level": identity_level,
        "identity_label": identity_meta["label"],
        "identity_icon": identity_meta["icon"],
        "first_contribution": first_contribution,
        "identity_badges": identity_badges,
        "login": display_login or None,
        "email": email or None,
        "display_name": display_name,
        "github_profile": profile_hint,
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
    
    repo = request.args.get("repo")
    sha = request.args.get("sha")
    branch = request.args.get("branch")

    if not repo or not sha:
        return "리포지토리와 커밋 SHA가 필요합니다.", 400

    return render_template("detail_view.html", 
        user_id=session.get("user_login") or "me",
        repo_name=repo,
        commit_sha=sha,
        branch_name=branch
    )

# ---------- API ----------
@app.get("/api/get_initial_data")
def get_initial_data():
    if "access_token" not in session: return jsonify({"error": "unauthorized"}), 401
    
    # 1. Repos 가져오기
    repos, _ = _gh_get(GITHUB_URL_REPOS, params={"per_page": 100, "sort": "pushed"})
    repos_list = [{"full_name": r.get("full_name"), "name": r.get("name"), "pushed_at": r.get("pushed_at")} for r in (repos or [])]
    
    branches_map = {}
    commits_map = {}

    # 2. 각 Repo의 Branch 및 Commit 가져오기
    for repo in repos_list:
        repo_name = repo['full_name']
        
        # Branches
        branch_url = GITHUB_URL_REPO_BRANCHES.format(repo=repo_name)
        branches_data, _ = _gh_get(branch_url, params={"per_page": 100})
        
        branch_list = []
        for b in (branches_data or []):
            sha = (b.get("commit") or {}).get("sha")
            commit_url = f"{GITHUB_URL_BASE}/repos/{repo_name}/commits/{sha}"
            try:
                commit_data, _ = _gh_get(commit_url)
                commit_date = (commit_data.get("commit", {}).get("author") or {}).get("date")
                branch_list.append({"name": b.get("name"), "sha": sha, "last_commit_date": commit_date})
            except requests.exceptions.RequestException:
                branch_list.append({"name": b.get("name"), "sha": sha, "last_commit_date": None})
        
        branches_map[repo_name] = branch_list

        # Commits (for each branch)
        for branch_info in branch_list:
            branch_name = branch_info['name']
            commit_url = GITHUB_URL_REPO_COMMITS.format(repo=repo_name)
            commits_data, _ = _gh_get(commit_url, params={"sha": branch_name, "per_page": COMMITS_PER_BRANCH})
            
            key = f"{repo_name}|{branch_name}"
            pick = lambda c: {"sha": c.get("sha"), "message": (c.get("commit", {}).get("message") or "").split("\n")[0], "author": (c.get("commit", {}).get("author") or {}).get("name"), "date": (c.get("commit", {}).get("author") or {}).get("date")}
            commits_map[key] = [pick(c) for c in (commits_data or [])]

    return jsonify({
        "repos": repos_list,
        "branches": branches_map,
        "commits": commits_map,
        "timestamp": datetime.utcnow().isoformat()
    })

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
    commits, _ = _gh_get(url, params={"sha": branch, "per_page": COMMITS_PER_BRANCH})
    pick = lambda c: {"sha": c.get("sha"), "message": (c.get("commit", {}).get("message") or "").split("\n")[0], "author": (c.get("commit", {}).get("author") or {}).get("name"), "date": (c.get("commit", {}).get("author") or {}).get("date")}
    return jsonify({"commits": [pick(c) for c in (commits or [])]})

@app.get("/api/commit_detail")
def api_commit_detail():
    repo, sha = (request.args.get("repo") or "").strip(), (request.args.get("sha") or "").strip()
    if not repo or not sha: return jsonify({"error": "repo and sha required"}), 400
    if "access_token" not in session: return jsonify({"error": "unauthorized"}), 401
    url = f"{GITHUB_URL_REPO_COMMITS.format(repo=repo)}/{sha}"
    data, _ = _gh_get(url)
    stats = data.get("stats") or {}
    commit = data.get("commit") or {}
    author_info = commit.get("author") or {}
    github_author = data.get("author") or {}
    github_committer = data.get("committer") or {}

    files_payload = []
    for file_info in data.get("files") or []:
        files_payload.append({
            "filename": file_info.get("filename"),
            "status": file_info.get("status"),
            "additions": file_info.get("additions"),
            "deletions": file_info.get("deletions"),
            "changes": file_info.get("changes"),
            "patch": file_info.get("patch"),
            "blob_url": file_info.get("blob_url"),
            "raw_url": file_info.get("raw_url"),
        })

    return jsonify({
        "message": commit.get("message"),
        "author": author_info.get("name"),
        "author_email": author_info.get("email"),
        "author_login": github_author.get("login") or github_committer.get("login"),
        "author_avatar": github_author.get("avatar_url") or github_committer.get("avatar_url"),
        "author_html_url": github_author.get("html_url") or github_committer.get("html_url"),
        "date": author_info.get("date"),
        "stats": {
            "total": stats.get("total"),
            "additions": stats.get("additions"),
            "deletions": stats.get("deletions"),
        },
        "files": files_payload,
        "html_url": data.get("html_url"),
        "verification": commit.get("verification"),
    })

@app.get("/api/commit_diff")
def api_commit_diff():
    repo, sha = request.args.get("repo"), request.args.get("sha")
    if not repo or not sha: return jsonify({"error": "repo and sha required"}), 400
    if "access_token" not in session: return jsonify({"error": "unauthorized"}), 401
    url = f"{GITHUB_URL_REPO_COMMITS.format(repo=repo)}/{sha}"
    diff_text, _ = _gh_get(url, accept_header="application/vnd.github.diff")
    return Response(diff_text, mimetype='text/plain')



@app.get("/api/commit_comments")
def api_commit_comments():
    repo = (request.args.get("repo") or "").strip()
    sha = (request.args.get("sha") or "").strip()
    if not repo or not sha:
        return jsonify({"error": "repo and sha required"}), 400
    if "access_token" not in session:
        return jsonify({"error": "unauthorized"}), 401
    url = f"{GITHUB_URL_BASE}/repos/{repo}/commits/{sha}/comments"
    try:
        comments, _ = _gh_get(url, params={"per_page": 100})
    except requests.exceptions.HTTPError as exc:
        status = exc.response.status_code if exc.response else 502
        return jsonify({"error": "failed to load comments"}), status
    except requests.exceptions.RequestException:
        log.exception("Failed to load commit comments for %s@%s", repo, sha)
        return jsonify({"error": "failed to load comments"}), 502
    normalized = [_normalize_commit_comment(c) for c in (comments or [])]
    return jsonify({"comments": normalized})


@app.post("/api/commit_comments")
def api_create_commit_comment():
    if "access_token" not in session:
        return jsonify({"error": "unauthorized"}), 401
    payload = request.get_json(silent=True) or {}
    repo = (payload.get("repo") or "").strip()
    sha = (payload.get("sha") or "").strip()
    body = (payload.get("body") or "").strip()
    if not repo or not sha or not body:
        return jsonify({"error": "repo, sha, and body are required"}), 400

    comment_payload = {"body": body}
    path = (payload.get("path") or "").strip()
    side = (payload.get("side") or "RIGHT").upper()
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

    url = f"{GITHUB_URL_BASE}/repos/{repo}/commits/{sha}/comments"
    try:
        response = requests.post(
            url,
            headers=_gh_headers(),
            json=comment_payload,
            timeout=TIMEOUT,
        )
        if response.status_code == 201:
            return jsonify({"comment": _normalize_commit_comment(response.json())}), 201
        if response.status_code == 422:
            return jsonify({"error": "invalid comment location", "details": response.json()}), 422
        response.raise_for_status()
    except requests.exceptions.HTTPError as exc:
        status = exc.response.status_code if exc.response else 502
        details = None
        if exc.response is not None:
            if "application/json" in exc.response.headers.get("Content-Type", ""):
                try:
                    details = exc.response.json()
                except ValueError:
                    details = exc.response.text
            else:
                details = exc.response.text
        log.warning("GitHub rejected commit comment creation: %s", details or exc)
        return jsonify({"error": "failed to create comment", "details": details}), status
    except requests.exceptions.RequestException:
        log.exception("GitHub API call failed while creating commit comment")
        return jsonify({"error": "failed to create comment"}), 502

    return jsonify({"error": "unexpected response"}), 502


@app.get("/api/repo_contributors")
def api_repo_contributors():
    repo = (request.args.get("repo") or "").strip()
    if not repo:
        return jsonify({"error": "repo required"}), 400
    if "access_token" not in session:
        return jsonify({"error": "unauthorized"}), 401
    url = f"{GITHUB_URL_BASE}/repos/{repo}/contributors"
    try:
        data, _ = _gh_get(url, params={"per_page": 100, "anon": "false"})
    except requests.exceptions.HTTPError as exc:
        status = exc.response.status_code if exc.response else 502
        return jsonify({"error": "failed to load contributors"}), status
    except requests.exceptions.RequestException:
        log.exception("Failed to load contributors for %s", repo)
        return jsonify({"error": "failed to load contributors"}), 502
    contributors = []
    for item in data or []:
        if not isinstance(item, dict):
            continue
        contributors.append({
            "login": item.get("login"),
            "contributions": item.get("contributions"),
            "avatar_url": item.get("avatar_url"),
            "html_url": item.get("html_url"),
            "type": item.get("type"),
            "site_admin": item.get("site_admin"),
        })
    return jsonify({"contributors": contributors})


@app.get("/api/developer_activity")
def api_developer_activity():
    repo = (request.args.get("repo") or "").strip()
    login = (request.args.get("login") or "").strip()
    if not repo or not login:
        return jsonify({"error": "repo and login required"}), 400
    if "access_token" not in session:
        return jsonify({"error": "unauthorized"}), 401

    commits_endpoint = GITHUB_URL_REPO_COMMITS.format(repo=repo)
    try:
        commits_data, _ = _gh_get(commits_endpoint, params={"author": login, "per_page": 10})
    except requests.exceptions.HTTPError as exc:
        status = exc.response.status_code if exc.response else 502
        return jsonify({"error": "failed to load commits"}), status
    except requests.exceptions.RequestException:
        log.exception("Failed to fetch commit history for %s in %s", login, repo)
        return jsonify({"error": "failed to load commits"}), 502

    commit_summaries = []
    hotspots_index = {}
    identity_snapshot = None

    for commit_entry in commits_data or []:
        sha = (commit_entry or {}).get("sha")
        if not sha:
            continue
        try:
            detail_data, _ = _gh_get(f"{commits_endpoint}/{sha}")
        except requests.exceptions.RequestException as exc:
            log.warning("Failed to fetch commit detail for %s@%s: %s", repo, sha, exc)
            continue

        commit_info = detail_data.get("commit") or {}
        stats = detail_data.get("stats") or {}
        author_info = commit_info.get("author") or {}

        file_summaries = []
        for file_info in detail_data.get("files") or []:
            filename = file_info.get("filename")
            additions = file_info.get("additions") or 0
            deletions = file_info.get("deletions") or 0
            change_count = file_info.get("changes")
            if change_count is None:
                change_count = additions + deletions
            file_summaries.append({
                "filename": filename,
                "status": file_info.get("status"),
                "additions": additions,
                "deletions": deletions,
                "changes": change_count,
            })
            if filename:
                hotspot = hotspots_index.setdefault(filename, {"filename": filename, "additions": 0, "deletions": 0, "changes": 0, "commits": 0})
                hotspot["additions"] += additions
                hotspot["deletions"] += deletions
                hotspot["changes"] += change_count
                hotspot["commits"] += 1

        commit_summaries.append({
            "sha": sha,
            "message": (commit_info.get("message") or "").split("\n")[0],
            "full_message": commit_info.get("message"),
            "date": author_info.get("date"),
            "html_url": detail_data.get("html_url"),
            "stats": {
                "total": stats.get("total"),
                "additions": stats.get("additions"),
                "deletions": stats.get("deletions"),
            },
            "files": file_summaries,
        })

        if identity_snapshot is None:
            identity_snapshot = _evaluate_identity_risk(
                author_info.get("email"),
                login,
                detail_data,
                repo_full_name=repo,
                current_commit_sha=sha,
            )

    hotspots = sorted(
        hotspots_index.values(),
        key=lambda item: (item["changes"], item["additions"] + item["deletions"]),
        reverse=True,
    )[:15]

    comments = []
    comments_url = f"{GITHUB_URL_BASE}/repos/{repo}/comments"
    try:
        comments_data, _ = _gh_get(comments_url, params={"per_page": 100})
    except requests.exceptions.RequestException as exc:
        log.warning("Failed to fetch commit comments for %s: %s", repo, exc)
        comments_data = []
    if comments_data:
        login_lower = login.lower()
        for comment in comments_data:
            user = (comment or {}).get("user") or {}
            if (user.get("login") or "").lower() != login_lower:
                continue
            comments.append(_normalize_commit_comment(comment))
            if len(comments) >= 30:
                break

    profile = {"login": login}
    try:
        profile_data, _ = _gh_get(f"{GITHUB_URL_BASE}/users/{login}")
    except requests.exceptions.RequestException as exc:
        log.warning("Failed to fetch user profile for %s: %s", login, exc)
        profile_data = None
    if isinstance(profile_data, dict):
        profile.update({
            "name": profile_data.get("name"),
            "company": profile_data.get("company"),
            "location": profile_data.get("location"),
            "html_url": profile_data.get("html_url"),
            "avatar_url": profile_data.get("avatar_url"),
            "bio": profile_data.get("bio"),
            "type": profile_data.get("type"),
        })

    return jsonify({
        "profile": profile,
        "identity": identity_snapshot,
        "recent_commits": commit_summaries,
        "code_hotspots": hotspots,
        "recent_comments": comments,
    })

@app.get("/api/security_status")
def api_security_status():
    repo = request.args.get("repo")
    commit_sha = request.args.get("commit") or request.args.get("sha")
    branch = request.args.get("branch")
    if not repo or not commit_sha:
        return jsonify({"error": "repo and commit required"}), 400
    if "access_token" not in session:
        return jsonify({"error": "unauthorized"}), 401

    commit_data = None
    author_email = None
    author_login = None
    commit_url = f"{GITHUB_URL_REPO_COMMITS.format(repo=repo)}/{commit_sha}"
    try:
        commit_data_json, _ = _gh_get(commit_url)
        if isinstance(commit_data_json, dict):
            commit_data = commit_data_json
    except requests.exceptions.RequestException as commit_err:
        log.warning("Failed to fetch commit %s@%s for identity assessment: %s", repo, commit_sha, commit_err)
        commit_data = None

    if isinstance(commit_data, dict):
        commit_info = (commit_data.get("commit") or {})
        author_info = commit_info.get("author") or {}
        author_email = (commit_data.get("author") or {}).get("email") or author_info.get("email")
        author_login = (commit_data.get("author") or {}).get("login") or (commit_data.get("committer") or {}).get("login") or author_info.get("name")

    identity_assessment = _evaluate_identity_risk(author_email, author_login, commit_data, repo_full_name=repo, current_commit_sha=commit_sha)

    branch_ref = None
    if branch:
        branch = branch.strip()
        if branch:
            branch_ref = branch if branch.startswith("refs/") else f"refs/heads/{branch}"

    params = {"per_page": 100}
    if branch_ref:
        params["ref"] = branch_ref

    url = f"{GITHUB_URL_BASE}/repos/{repo}/code-scanning/alerts"
    try:
        alerts, _ = _gh_get(url, params=params)
        alerts = alerts or []

        def _matches_commit(alert):
            if not commit_sha:
                return True
            target = commit_sha.lower()
            candidates = []
            candidates.append(alert.get('most_recent_instance') or {})
            candidates.extend(alert.get('instances') or [])
            for inst in candidates:
                sha = (inst or {}).get('commit_sha')
                if sha and sha.lower() == target:
                    return True
            return False

        commit_alerts = [a for a in alerts if _matches_commit(a)]

        enriched_alerts = []
        for alert in commit_alerts[:10]:
            rule = alert.get('rule') or {}
            severity = (rule.get('severity') or '').lower()
            most_recent = alert.get('most_recent_instance') or {}
            location = most_recent.get('location') or {}
            message = (most_recent.get('message') or {}).get('text') or alert.get('description') or ''
            path_name = location.get('path') or ''
            start_line = location.get('start_line') or 0
            end_line = location.get('end_line') or start_line or 0
            excerpt = _get_code_excerpt(repo, commit_sha, path_name, start_line, end_line)
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

        high_alerts = [a for a in commit_alerts if (a.get('rule') or {}).get('severity', '').lower() in {'critical', 'high'}]
        defender_status = 'bad' if high_alerts else 'warn' if commit_alerts else 'good'
        defender_summary = f"CodeQL 경고: {len(commit_alerts)}"

        sentinel = identity_assessment

        bricks = {
            'status': 'unknown',
            'summary': 'Databricks 이상 점수를 대기 중입니다.',
            'details': ['Databricks 이상 점수를 대기 중입니다.'],
        }

        try:
            bricks_features = _build_bricks_features_from_commit(repo, commit_sha, commit_data=commit_data)

            if bricks_features:
                anomaly_score = _invoke_databricks_model(bricks_features)
                if anomaly_score is not None:
                    bricks_status = 'bad' if anomaly_score >= 0.8 else 'warn' if anomaly_score >= 0.5 else 'good'
                    score_text = f"{anomaly_score:.1f}"
                    bricks = {
                        'status': bricks_status,
                        'summary': score_text,
                        'score': anomaly_score,
                        'features': bricks_features,
                        'details': [f"Anomaly score: {anomaly_score:.3f}"],
                    }
                else:
                    bricks = {
                        'status': 'unknown',
                        'summary': 'Databricks 응답에 anomaly_score가 없습니다.',
                        'features': bricks_features,
                        'details': ['Databricks 응답에 anomaly_score가 없습니다.'],
                    }
            else:
                bricks = {
                    'status': 'unknown',
                    'summary': '모델 입력 데이터를 생성하지 못했습니다.',
                    'details': ['모델 입력 데이터를 생성하지 못했습니다.'],
                }
        except RuntimeError as cfg_err:
            log.warning('Databricks configuration error: %s', cfg_err)
            bricks = {
                'status': 'unknown',
                'summary': 'Databricks 구성 오류가 발생했습니다.',
                'details': ['Databricks 구성 오류가 발생했습니다.'],
            }
        except requests.exceptions.RequestException:
            log.exception('Databricks model invocation failed')
            bricks = {
                'status': 'unknown',
                'summary': 'Databricks 모델 호출에 실패했습니다.',
                'details': ['Databricks 모델 호출에 실패했습니다.'],
            }
        except Exception:
            log.exception('Unexpected error while calling Databricks model')
            bricks = {
                'status': 'unknown',
                'summary': 'Databricks 모델 처리 중 알 수 없는 오류가 발생했습니다.',
                'details': ['Databricks 모델 처리 중 알 수 없는 오류가 발생했습니다.'],
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
                'defender': {'status': 'unknown', 'summary': 'No results', 'alerts': []},
                'sentinel': identity_assessment,
                'bricks': {'status': 'unknown', 'summary': 'Databricks 결과 없음', 'details': ['Databricks 결과 없음']},
            })
        raise
    except Exception:
        log.exception(f"Failed to get security status for {repo}@{commit_sha}")
        return jsonify(error="보안 상태를 불러오지 못했습니다."), 500

@app.errorhandler(PermissionError)
def _unauth(_):
    session.clear()
    # If request is API, return JSON 401; otherwise redirect.
    if request.path.startswith("/api/"):
        return jsonify({"error": "unauthorized"}), 401
    return redirect(url_for("index"))

@app.errorhandler(Exception)
def handle_exception(e):
    if hasattr(e, 'code') and isinstance(e.code, int) and 400 <= e.code < 600: return e
    log.exception("An unhandled exception occurred")
    return jsonify(error="Internal server error"), 500

if __name__ == "__main__":
    debug_mode = os.environ.get("FLASK_DEBUG", "").lower() in {"1", "true", "yes"}
    port = int(os.environ.get("PORT", "8000"))
    app.run(host="0.0.0.0", port=port, debug=debug_mode)