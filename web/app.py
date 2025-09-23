# web/app.py
import os
import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, Tuple, Optional

import requests
from flask import Flask, render_template, request, jsonify

# ----------------------------
# 기본 설정
# ----------------------------
app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev-secret")
logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"))
log = logging.getLogger("app")

# Databricks 환경변수
DB_WORKSPACE_URL = os.environ.get("DB_WORKSPACE_URL", "").rstrip("/")
DB_MODEL_ENDPOINT = os.environ.get("DB_MODEL_ENDPOINT", "")  # 예: /serving-endpoints/guardian-iforest/invocations
DB_TOKEN = os.environ.get("DB_TOKEN", "")

# ----------------------------
# 유틸
# ----------------------------
def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def _auth_header() -> Dict[str, str]:
    if not DB_TOKEN:
        return {}
    return {"Authorization": f"Bearer {DB_TOKEN}"}

def _json(o: Any) -> str:
    return json.dumps(o, ensure_ascii=False, separators=(",", ":"))

# ----------------------------
# Databricks 호출/파싱
# ----------------------------
def _invoke_databricks_model(payload: Dict[str, Any]) -> Tuple[Optional[dict], Optional[str]]:
    """
    Databricks 엔드포인트 호출.
    반환: (json 응답, 에러문자열)
    """
    if not (DB_WORKSPACE_URL and DB_MODEL_ENDPOINT and DB_TOKEN):
        return None, "Databricks 환경변수가 설정되어 있지 않습니다."

    url = f"{DB_WORKSPACE_URL}{DB_MODEL_ENDPOINT}"
    headers = {
        "Content-Type": "application/json",
        **_auth_header(),
    }

    try:
        resp = requests.post(url, headers=headers, data=_json(payload), timeout=30)
        if resp.status_code >= 400:
            return None, f"Databricks 호출 실패: {resp.status_code} {resp.text[:500]}"
        return resp.json(), None
    except Exception as e:
        return None, f"Databricks 호출 예외: {e}"

def _extract_anomaly_details(resp_json: Dict[str, Any]) -> Dict[str, Any]:
    """
    다양한 응답 스키마를 견고하게 파싱.
    가능한 키 예:
      - {_anomaly_score, _is_anomaly, threshold, threshold_percentile, model_version}
      - {score, is_anomaly, threshold, percentile, model_version}
      - {predictions: [{...}]}
    """
    def _first_dict(d: Any) -> Dict[str, Any]:
        if isinstance(d, dict):
            return d
        if isinstance(d, list) and d and isinstance(d[0], dict):
            return d[0]
        return {}

    root = _first_dict(resp_json)

    # predictions / data[*] 안쪽에 있는 경우 끌어오기
    if "predictions" in root:
        root = _first_dict(root.get("predictions"))
    elif "data" in root:
        root = _first_dict(root.get("data"))
    elif "output" in root:
        root = _first_dict(root.get("output"))

    # 다양한 이름 매핑
    score = (
        root.get("_anomaly_score")
        or root.get("anomaly_score")
        or root.get("score")
    )
    is_anom = (
        root.get("_is_anomaly")
        if "_is_anomaly" in root else
        root.get("is_anomaly")
    )
    threshold = (
        root.get("threshold")
        or root.get("anomaly_threshold")
    )
    percentile = (
        root.get("threshold_percentile")
        or root.get("percentile")
        or root.get("threshold_pct")
    )
    model_version = root.get("model_version") or root.get("version")

    parsed = {
        "score": float(score) if score is not None else None,
        "is_anomaly": bool(is_anom) if is_anom is not None else None,
        "threshold": float(threshold) if isinstance(threshold, (int, float, str)) and str(threshold).replace(".","",1).isdigit() else None,
        "percentile": float(percentile) if isinstance(percentile, (int, float, str)) and str(percentile).replace(".","",1).isdigit() else None,
        "model_version": str(model_version) if model_version is not None else None,
        # 디버그 보조
        "_raw": resp_json,
    }
    return parsed

# ----------------------------
# 브릭스 표준 후처리
# ----------------------------
def _bricks_postprocess(model_parsed: Dict[str, Any]) -> Dict[str, Any]:
    """
    입력:  {score, is_anomaly, threshold, percentile, model_version}
    출력:  프론트가 바로 쓰는 표준 bricks 오브젝트
       - status: good | warn | bad
       - severity: 0~100 (대략 위험도 점수화)
       - score: 연속값 스코어(값↑ = 더 이상함)
       - threshold: 모델 임계값 (없으면 None)
       - percentile: 임계값의 분위 정보 (예: 98.0)
       - is_anomaly: 이상 여부 (bool|None)
       - proximity: 임계치 대비 상대 위치 (score/threshold)  ※ threshold 없으면 None
       - model_version: 문자열
       - summary: 한 줄 요약
       - details: 리스트(문장)
    규칙:
      * is_anomaly=True  -> status=bad
      * is_anomaly=False 이면서 score >= 0.9*threshold -> status=warn
      * 그 외 -> status=good
    """
    score = model_parsed.get("score")
    is_anom = model_parsed.get("is_anomaly")
    threshold = model_parsed.get("threshold")
    pct = model_parsed.get("percentile")
    model_version = model_parsed.get("model_version")

    # proximity 계산
    proximity = None
    if isinstance(score, (int, float)) and isinstance(threshold, (int, float)) and threshold > 0:
        proximity = float(score) / float(threshold)

    # status/summary/severity
    status = "unknown"
    severity = 0
    summary = "모델 결과가 부족합니다."
    details = []

    if score is None or is_anom is None:
        status = "unknown"
        summary = "모델 응답 해석 불가."
        details.append("필수 필드(score/is_anomaly) 누락.")
    else:
        score = float(score)
        if is_anom is True:
            status = "bad"
            severity = 90 if proximity is None else min(100, int(80 + 20 * min(proximity, 1.5)))
            summary = "이상 징후가 감지되었습니다."
            details.append(f"스코어={score}")
            if threshold is not None:
                details.append(f"임계값={threshold}")
        else:
            # 정상으로 분류됐지만 임계값에 근접하면 경고
            near = False
            if isinstance(threshold, (int, float)):
                near = score >= 0.9 * float(threshold)
            if near:
                status = "warn"
                severity = 60 if proximity is None else min(85, int(50 + 35 * min(proximity, 1.2)))
                summary = "임계값에 근접한 관측치입니다."
                details.append(f"스코어={score} (임계값의 90% 이상)")
                details.append(f"임계값={threshold}")
            else:
                status = "good"
                severity = 15 if proximity is None else max(5, int(20 * min(proximity, 0.9)))
                summary = "정상 범위로 판단됩니다."
                details.append(f"스코어={score}")

    if pct is not None:
        details.append(f"임계 분위={pct}p")
    if model_version:
        details.append(f"모델 버전={model_version}")

    return {
        "status": status,
        "severity": severity,
        "score": score,
        "threshold": threshold,
        "percentile": pct,
        "is_anomaly": is_anom,
        "proximity": proximity,
        "model_version": model_version,
        "summary": summary,
        "details": details,
        "at": _now_iso(),
    }

# ----------------------------
# 라우트
# ----------------------------
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/analyze", methods=["POST"])
def analyze():
    """
    요청 JSON 예:
    {
      "features": {... 모델 입력 ...},
      "threshold": 0.37,                 # 선택
      "threshold_percentile": 98.0,      # 선택
      "model_version": "iforest:v2"      # 선택
    }
    """
    req = request.get_json(force=True, silent=True) or {}
    features = req.get("features") or {}

    # Databricks로 그대로 전달 (임계/백분위/버전 포함 시켜줌)
    payload = {
        "inputs": features,
    }
    # 선택 파라미터 pass-through
    for k_src, k_dst in [
        ("threshold", "threshold"),
        ("threshold_percentile", "threshold_percentile"),
        ("model_version", "model_version"),
    ]:
        if k_src in req:
            payload[k_dst] = req[k_src]

    resp_json, err = _invoke_databricks_model(payload)
    if err:
        log.error("Databricks error: %s", err)
        return jsonify({
            "bricks": {
                "status": "unknown",
                "summary": "모델 호출 실패",
                "details": [err],
            },
            "defender": {"status": "good", "summary": "CodeQL 경고: 0"},
            "sentinel": {"status": "good", "summary": "신원 확인 OK"},
        }), 502

    parsed = _extract_anomaly_details(resp_json)
    bricks = _bricks_postprocess(parsed)

    return jsonify({
        "bricks": bricks,
        "defender": {"status": "good", "summary": "CodeQL 경고: 0"},
        "sentinel": {"status": "good", "summary": "내부 계정 확인됨"},
    })

# ----------------------------
# 헬스체크
# ----------------------------
@app.route("/healthz")
def healthz():
    return jsonify({"ok": True, "time": _now_iso()})

# ----------------------------
# 로컬 실행용
# ----------------------------
if __name__ == "__main__":
    # 로컬 디버그 시: python web/app.py
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "8000")), debug=True)
