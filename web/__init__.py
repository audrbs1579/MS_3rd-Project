import logging
import os
import hmac
import hashlib
import json
import requests
import azure.functions as func
from datetime import datetime
from azure.cosmos import CosmosClient, exceptions

# --- 설정 ---
COSMOS_CONNECTION_STRING = os.environ.get("COSMOS_DB_CONNECTION_STRING")
GH_SECRET = os.environ.get("GITHUB_WEBHOOK_SECRET", "").encode("utf-8")
GH_PAT = os.environ.get("GITHUB_PAT")
GITHUB_API_URL = "https://api.github.com"
COSMOS_DATABASE_NAME = "ProjectGuardianDB"
COSMOS_REPOS_CONTAINER = "repositories"
COSMOS_COMMITS_CONTAINER = "commits"
COSMOS_EVENTS_CONTAINER = "events"

# --- Cosmos DB 클라이언트 초기화 ---
try:
    cosmos_client = CosmosClient.from_connection_string(COSMOS_CONNECTION_STRING)
    database_client = cosmos_client.get_database_client(COSMOS_DATABASE_NAME)
    repos_container = database_client.get_container_client(COSMOS_REPOS_CONTAINER)
    commits_container = database_client.get_container_client(COSMOS_COMMITS_CONTAINER)
    events_container = database_client.get_container_client(COSMOS_EVENTS_CONTAINER)
except Exception as e:
    logging.error(f"Failed to initialize Cosmos DB client: {e}")
    raise

# --- GitHub API 호출 헬퍼 ---
def gh_api_get(url):
    headers = {'Authorization': f'token {GH_PAT}', 'Accept': 'application/vnd.github+json'}
    res = requests.get(url, headers=headers, timeout=20)
    res.raise_for_status()
    return res.json()

def verify_signature(body: bytes, signature: str) -> bool:
    if not signature or not signature.startswith("sha256="):
        return False
    sig_hash = signature.split("=", 1)[1]
    expected = hmac.new(GH_SECRET, msg=body, digestmod=hashlib.sha256).hexdigest()
    return hmac.compare_digest(sig_hash, expected)

def main(req: func.HttpRequest) -> func.HttpResponse:
    signature = req.headers.get("X-Hub-Signature-256", "")
    event_type = req.headers.get("X-GitHub-Event", "")
    delivery_id = req.headers.get("X-GitHub-Delivery")
    body = req.get_body()

    if not verify_signature(body, signature):
        logging.warning("Invalid signature.")
        return func.HttpResponse("Invalid signature", status_code=403)

    if event_type != 'push':
        logging.info(f"Event '{event_type}' is not a 'push' event, skipping.")
        return func.HttpResponse(f"Event '{event_type}' is not supported.", status_code=200)

    try:
        payload = json.loads(body)

        # --- events 컨테이너에 원본 로그 저장 ---
        if delivery_id:
            try:
                event_doc = {
                    'id': delivery_id,
                    'eventType': event_type,
                    'payload': payload,
                    'timestamp': datetime.utcnow().isoformat()
                }
                # events 컨테이너의 파티션 키가 '/eventType'이라면 아래와 같이 설정
                # events_container.upsert_item(event_doc, partition_key=event_type)
                events_container.upsert_item(event_doc)
                logging.info(f"Logged event {delivery_id} to events container.")
            except Exception as e:
                log.warning(f"Failed to log event {delivery_id} to Cosmos DB: {e}")

        # --- 데이터 동기화 로직 ---
        repo_info = payload.get('repository', {})
        repo_full_name = repo_info.get('full_name')
        repo_owner_login = repo_info.get('owner', {}).get('login')
        branch_ref = payload.get('ref', '')

        if not repo_full_name or not repo_owner_login or not branch_ref.startswith('refs/heads/'):
            return func.HttpResponse("Invalid payload: missing repo_full_name, owner, or valid ref.", status_code=400)
            
        branch_name = branch_ref.split('/')[-1]

        # 1. `repositories` 컨테이너 업데이트
        log.info(f"Updating repository info for {repo_full_name} in Cosmos DB.")
        
        branches_data = gh_api_get(f"{GITHUB_API_URL}/repos/{repo_full_name}/branches")
        branches_list = [
            {"name": b.get("name"), "sha": (b.get("commit") or {}).get("sha")}
            for b in branches_data
        ]
        
        repo_doc = {
            'id': repo_full_name.replace('/', '-'), # ID에서 '/'를 '-'로 치환
            'repoFullName': repo_full_name,
            'userId': repo_owner_login,
            'repoName': repo_info.get('name'),
            'pushed_at': repo_info.get('pushed_at'),
            'branches': branches_list
        }
        repos_container.upsert_item(repo_doc)
        log.info(f"Successfully upserted repository: {repo_full_name}")

        # 2. `commits` 컨테이너 업데이트
        commits_from_push = payload.get('commits', [])
        if not commits_from_push:
            log.info("No new commits in this push. Exiting.")
            return func.HttpResponse("OK, no commits to process.", status_code=200)

        log.info(f"Processing {len(commits_from_push)} commits for {repo_full_name} on branch {branch_name}.")
        for commit in commits_from_push:
            commit_sha = commit.get('id')
            if not commit_sha:
                continue
            
            commit_doc = {
                'id': commit_sha,
                'sha': commit_sha,
                'repoFullName': repo_full_name,
                'branch': branch_name,
                'message': commit.get('message', '').split('\n')[0],
                'author': commit.get('author', {}).get('name'),
                'date': commit.get('timestamp'),
                'securityStatus': None
            }
            commits_container.upsert_item(commit_doc)
            log.info(f"Upserted basic info for commit: {commit_sha}")
            
        return func.HttpResponse(f"Successfully processed push for {repo_full_name}.", status_code=200)

    except json.JSONDecodeError:
        logging.exception("Failed to decode JSON from webhook body")
        return func.HttpResponse("Invalid JSON format.", status_code=400)
    except requests.exceptions.HTTPError as e:
        logging.exception(f"HTTP error during GitHub API call")
        return func.HttpResponse(f"GitHub API error: {e.response.status_code} - {e.response.text}", status_code=e.response.status_code)
    except Exception as e:
        logging.exception(f"Failed to process webhook")
        return func.HttpResponse(f"An unexpected error occurred: {str(e)}", status_code=500)