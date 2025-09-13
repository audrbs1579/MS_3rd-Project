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
        return func.HttpResponse(f"Event '{event_type}' is not supported.", status_code=200)

    try:
        payload = json.loads(body)
        repo_full_name = payload.get('repository', {}).get('full_name')
        if not repo_full_name:
            return func.HttpResponse("Repository name not found in webhook payload.", status_code=400)

        headers = {'Authorization': f'token {GH_PAT}', 'Accept': 'application/vnd.github+json'}
        sbom_url = f"{GITHUB_API_URL}/repos/{repo_full_name}/dependency-graph/sbom"
        sbom_res = requests.get(sbom_url, headers=headers)

        dependencies = []
        if sbom_res.status_code == 200:
            sbom_data = sbom_res.json().get('sbom', {})
            packages = sbom_data.get('packages', [])
            repo_name = repo_full_name.split('/')[1].lower() if '/' in repo_full_name else ''
            for pkg in packages:
                name = pkg.get('name', '')
                version = pkg.get('versionInfo', '')
                if name and repo_name not in name.lower():
                    dependencies.append(f"{name} {version}".strip())
        else:
            return func.HttpResponse(
                f"Error fetching dependency graph: {sbom_res.status_code} - {sbom_res.text}",
                status_code=500
            )

        result_json = json.dumps({
            "repository": repo_full_name,
            "dependency_count": len(dependencies),
            "dependencies": sorted(dependencies)
        }, indent=2)

        return func.HttpResponse(result_json, mimetype="application/json", status_code=200)

    except Exception as e:
        logging.exception("Failed to process webhook")
        return func.HttpResponse(f"Error: {str(e)}", status_code=500)
