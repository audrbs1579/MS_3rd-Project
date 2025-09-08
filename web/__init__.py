import logging
import os
import hmac
import hashlib
import json
import requests
import azure.functions as func

# --- 환경 변수 불러오기 ---
# GitHub 웹훅 시크릿. 웹훅의 무결성 검증에 사용됩니다.
GH_SECRET = os.environ.get("GITHUB_WEBHOOK_SECRET", "").encode("utf-8")
# GitHub API 호출을 위한 개인용 액세스 토큰(PAT). 'repo' 권한이 필요합니다.
GH_PAT = os.environ.get("GITHUB_PAT", "")

GITHUB_API_URL = "https://api.github.com"

# --- GitHub 서명 확인 함수 (기존과 동일) ---
def verify_signature(body: bytes, signature: str) -> bool:
    if not signature or not signature.startswith("sha256="):
        return False
    sig_hash = signature.split("=", 1)[1]
    expected = hmac.new(GH_SECRET, msg=body, digestmod=hashlib.sha256).hexdigest()
    return hmac.compare_digest(sig_hash, expected)

# --- 메인 함수 ---
def main(req: func.HttpRequest) -> func.HttpResponse:
    # GitHub 웹훅 헤더 정보 추출
    signature = req.headers.get("X-Hub-Signature-256", "")
    event_type = req.headers.get("X-GitHub-Event", "")
    
    body = req.get_body()

    # 서명 검증
    if not verify_signature(body, signature):
        logging.warning("Invalid signature.")
        return func.HttpResponse("Invalid signature", status_code=403)

    # 이 함수는 'push' 이벤트에 대해서만 작동하도록 설정
    if event_type != 'push':
        return func.HttpResponse(f"Event '{event_type}' is not supported.", status_code=200)

    try:
        payload = json.loads(body)
        repo_full_name = payload.get('repository', {}).get('full_name')

        if not repo_full_name:
            return func.HttpResponse("Repository name not found in webhook payload.", status_code=400)
        
        # --- GitHub API 호출하여 의존성 목록 가져오기 ---
        headers = {
            'Authorization': f'token {GH_PAT}',
            'Accept': 'application/vnd.github+json'
        }
        sbom_url = f"{GITHUB_API_URL}/repos/{repo_full_name}/dependency-graph/sbom"
        sbom_res = requests.get(sbom_url, headers=headers)
        
        dependencies = []
        if sbom_res.status_code == 200:
            sbom_data = sbom_res.json().get('sbom', {})
            packages = sbom_data.get('packages', [])
            for pkg in packages:
                name = pkg.get('name', '')
                version = pkg.get('versionInfo', '')
                # 자기 자신은 제외하고 이름이 있는 경우에만 추가
                if name and repo_full_name.split('/')[1].lower() not in name.lower():
                    dependencies.append(f"{name} {version}".strip())
        else:
            return func.HttpResponse(
                f"Error fetching dependency graph: {sbom_res.status_code} - {sbom_res.text}",
                status_code=500
            )
            
        # --- 결과를 JSON 형태로 반환 ---
        result_json = json.dumps({
            "repository": repo_full_name,
            "dependency_count": len(dependencies),
            "dependencies": sorted(dependencies)
        }, indent=2)

        return func.HttpResponse(result_json, mimetype="application/json", status_code=200)

    except Exception as e:
        logging.exception("Failed to process webhook")
        return func.HttpResponse(f"Error: {str(e)}", status_code=500)