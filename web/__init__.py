import logging
import os
import hmac
import hashlib
import json
import requests
import azure.functions as func

GH_SECRET = os.environ.get("GITHUB_WEBHOOK_SECRET", "").encode("utf-8")
GH_PAT = os.environ.get("GITHUB_PAT", "")
GITHUB_API_URL = "https://api.github.com"

def verify_signature(body: bytes, signature: str) -> bool:
    if not signature or not signature.startswith("sha256="):
        return False
    sig_hash = signature.split("=", 1)[1]
    expected = hmac.new(GH_SECRET, msg=body, digestmod=hashlib.sha256).hexdigest()
    return hmac.compare_digest(sig_hash, expected)

def main(req: func.HttpRequest) -> func.HttpResponse:
    signature = req.headers.get("X-Hub-Signature-256", "")
    event_type = req.headers.get("X-GitHub-Event", "")
    body = req.get_body()

    if not verify_signature(body, signature):
        logging.warning("Invalid signature.")
        return func.HttpResponse("Invalid signature", status_code=403)

    if event_type != 'push':
        logging.info(f"Event '{event_type}' is not a 'push' event, skipping.")
        return func.HttpResponse(f"Event '{event_type}' is not supported.", status_code=200)

    try:
        payload = json.loads(body)
        repo_full_name = payload.get('repository', {}).get('full_name')
        if not repo_full_name:
            logging.error("Repository full_name not found in webhook payload.")
            return func.HttpResponse("Repository name not found in webhook payload.", status_code=400)

        headers = {'Authorization': f'token {GH_PAT}', 'Accept': 'application/vnd.github+json'}
        sbom_url = f"{GITHUB_API_URL}/repos/{repo_full_name}/dependency-graph/sbom"
        
        logging.info(f"Fetching SBOM for repository: {repo_full_name}")
        sbom_res = requests.get(sbom_url, headers=headers, timeout=20) # Added timeout
        sbom_res.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)

        dependencies = []
        sbom_data = sbom_res.json().get('sbom', {})
        packages = sbom_data.get('packages', [])
        
        # [OPTIMIZED] Simplified repo_name extraction and comparison
        repo_name_lower = repo_full_name.split('/')[1].lower() if '/' in repo_full_name else ''
        
        for pkg in packages:
            name = pkg.get('name', '')
            version = pkg.get('versionInfo', '')
            # Exclude the repository's own package from the dependency list
            if name and repo_name_lower not in name.lower():
                dependencies.append(f"{name} {version}".strip())

        result_json = json.dumps({
            "repository": repo_full_name,
            "dependency_count": len(dependencies),
            "dependencies": sorted(dependencies)
        }, indent=2)

        return func.HttpResponse(result_json, mimetype="application/json", status_code=200)

    # [OPTIMIZED] More specific exception handling
    except json.JSONDecodeError:
        logging.exception("Failed to decode JSON from webhook body")
        return func.HttpResponse("Invalid JSON format in request body.", status_code=400)
    except requests.exceptions.HTTPError as e:
        logging.exception(f"HTTP error while fetching SBOM for {repo_full_name}")
        return func.HttpResponse(
            f"Error fetching dependency graph: {e.response.status_code} - {e.response.text}",
            status_code=e.response.status_code
        )
    except Exception as e:
        logging.exception(f"Failed to process webhook for {repo_full_name}")
        return func.HttpResponse(f"An unexpected error occurred: {str(e)}", status_code=500)