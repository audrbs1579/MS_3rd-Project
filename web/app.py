# app.py
# -*- coding: utf-8 -*-
"""
Project Guardian - Web API (Flask)
- Databricks 이상탐지 응답 파서 강화 (_extract_anomaly_details)
- threshold, threshold_percentile, model_version 파라미터 투과(_invoke_databricks_model)
- 브릭스 표준 포스트프로세서(_bricks_postprocess)
- /analyze 엔드포인트에서 bricks 오브젝트로 일관 응답
"""

from __future__ import annotations
import os
import json
import math
import logging
from datetime import datetime, timezone
from typing import Any, Dict, Tuple, Optional, List

import requests
from flask import Flask, jsonify, request, send_from_directory

# -----------------------------------------------------------------------------
# 기본 설정
# -----------------------------------------------------------------------------
ROOT = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = ROOT  # index.html 이 같은 폴더에 있다고 가정 (web/)
JSONIFY_PRETTYPRINT_REGULAR = False

logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO"),
    format="%(asctime)s | %(levelname)s | %(message)s",
)
logger = logging.getLogger("guardian")

app = Flask(
    __name__,
    static_folder=None,
)
app.config["JSON_SORT_KEYS"] = False


# -----------------------------------------------------------------------------
# 유틸
# -----------------------------------------------------------------------------
def _now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def _to_float(x: Any) -> Optional[float]:
    try:
        if x is None:
            return None
        return float(x)
    except Exception:
        return None


def _safe_get(d: Dict, *path, default=None):
    cur = d
    for k in path:
        if not isinstance(cur, (dict, list)):
            return default
        if isinstance(cur, list):
            # 정수 인덱스만 허용
            if isinstance(k, int) and 0 <= k < len(cur):
                cur = cur[k]
            else:
                return default
        else:
            cur = cur.get(k, default)
    return cur


# -----------------------------------------------------------------------------
# 1) Databricks 호출 (없으면 페일세이프/로컬 대체)
# -----------------------------------------------------------------------------
def _invoke_databricks_model(
    features: Dict[str, Any],
    threshold: Optional[float],
    threshold_percentile: Optional[float],
    model_version: Optional[str],
) -> Dict[str, Any]:
    """
    통신에러·미설정시에도 항상 표준 키로 돌아오도록 보장.
    반환(dict)은 가능한 넓은 superset:
      {
        "raw": {...원본 또는 대체산출...},
        "score": float,
        "is_anomaly": bool,
        "threshold": float|None,
        "percentile": float|None,
        "model_version": str|None,
        "details": [str, ...]
      }
    """
    db_url = os.environ.get("DATABRICKS_MODEL_URL")
    db_token = os.environ.get("DATABRICKS_TOKEN")

    # --- 실 호출 경로 ---
    if db_url and db_token:
        try:
            payload = {
                "features": features,
                # 요청자가 넘긴 파라미터는 그대로 전파
                "threshold": threshold,
                "threshold_percentile": threshold_percentile,
                "model_version": model_version,
            }
            headers = {
                "Authorization": f"Bearer {db_token}",
                "Content-Type": "application/json",
            }
            resp = requests.post(db_url, headers=headers, json=payload, timeout=15)
            resp.raise_for_status()
            raw = resp.json()
            parsed = _extract_anomaly_details(raw)

            # 요청에서 받은 파라미터는 우선 보존 (서버가 값 주면 서버 값을 우선)
            if threshold is not None and parsed.get("threshold") is None:
                parsed["threshold"] = threshold
            if threshold_percentile is not None and parsed.get("percentile") is None:
                parsed["percentile"] = threshold_percentile
            if model_version and not parsed.get("model_version"):
                parsed["model_version"] = model_version

            parsed["raw"] = raw
            return parsed
        except Exception as e:
            logger.exception("Databricks call failed: %s", e)

    # --- 페일세이프: 팀원 산출 규칙 반영 ---
    # 팀에서 말한 규칙:
    #  - 연속값 스코어: _anomaly_score (IsolationForest.score_samples(X)의 부호 반전)
    #    값이 클수록 더 이상함
    #  - 이상 여부: _is_anomaly (bool) 또는 threshold/percentile 기준 판정
    score = (
        _to_float(features.get("_anomaly_score"))
        or _to_float(features.get("anomaly_score"))
        or _to_float(features.get("score"))
        or 0.0
    )
    flag = features.get("_is_anomaly")
    if isinstance(flag, str):
        flag = flag.lower() in ("true", "1", "yes")
    elif not isinstance(flag, bool):
        flag = None

    dets = ["Databricks 호출 불가 → 로컬 대체 스코어 사용"]

    # threshold 우선순위: 명시 threshold > percentile로 추정 > 미정(None)
    thr = _to_float(threshold)
    pct = _to_float(threshold_percentile)
    if thr is None and pct is not None and score is not None:
        # 정보가 없으니 간단히 분위수 대용 추정(안전하게 높은 문턱)
        # p98라면 score*1.05 같은 보수적 추정
        thr = score * (1.05 if pct >= 98 else 1.02)
        dets.append(f"임시 임계값 추정 (percentile={pct})")

    if flag is None and thr is not None and score is not None:
        flag = bool(score >= thr)
        dets.append("임계값 기반으로 is_anomaly 판정")

    return {
        "raw": {"fallback": True, "features_echo": features},
        "score": float(score or 0.0),
        "is_anomaly": bool(flag) if flag is not None else False,
        "threshold": thr,
        "percentile": pct,
        "model_version": model_version,
        "details": dets,
    }


# -----------------------------------------------------------------------------
# 2) Databricks 응답 파서 (다양한 스키마 허용)
# -----------------------------------------------------------------------------
def _extract_anomaly_details(raw: Dict[str, Any]) -> Dict[str, Any]:
    """
    다양한 응답 스키마를 수용해서 표준 키로 정규화.
    가능한 소스 예:
      - {"score":..., "is_anomaly":..., "threshold":..., "percentile":..., "model_version":...}
      - {"data":{"score":...,"flag":...}}
      - {"prediction":{"anomaly":{"score":...,"is_anomaly":...}}}
      - {"bricks":{"score":...,"is_anomaly":...,"threshold":...}}
      - {"details":[...]} 등
    """
    dets: List[str] = []

    # 직접 키
    score = _to_float(raw.get("score"))
    is_anomaly = raw.get("is_anomaly")
    thr = _to_float(raw.get("threshold"))
    pct = _to_float(raw.get("percentile") or raw.get("threshold_percentile"))
    version = raw.get("model_version") or raw.get("version")

    # 흔한 네스팅
    if score is None:
        score = _to_float(_safe_get(raw, "data", "score")) or _to_float(
            _safe_get(raw, "prediction", "score")
        ) or _to_float(_safe_get(raw, "output", "score"))

    # bricks 안쪽
    if score is None:
        score = _to_float(_safe_get(raw, "bricks", "score"))

    # flag 위치들
    if is_anomaly is None:
        is_anomaly = _safe_get(raw, "data", "is_anomaly")
    if is_anomaly is None:
        is_anomaly = _safe_get(raw, "prediction", "is_anomaly")
    if is_anomaly is None:
        is_anomaly = _safe_get(raw, "output", "is_anomaly")
    if is_anomaly is None:
        is_anomaly = _safe_get(raw, "bricks", "is_anomaly")

    # boolean 정규화
    if isinstance(is_anomaly, str):
        is_anomaly = is_anomaly.lower() in ("true", "1", "yes")

    # threshold / percentile 보강
    if thr is None:
        thr = _to_float(_safe_get(raw, "data", "threshold")) or _to_float(
            _safe_get(raw, "prediction", "threshold")
        ) or _to_float(_safe_get(raw, "bricks", "threshold"))

    if pct is None:
        pct = _to_float(_safe_get(raw, "data", "percentile")) or _to_float(
            _safe_get(raw, "prediction", "percentile")
        ) or _to_float(_safe_get(raw, "bricks", "percentile"))

    if version is None:
        version = _safe_get(raw, "data", "model_version") or _safe_get(
            raw, "bricks", "model_version"
        )

    # details
    details_lst = []
    # 문자열 배열이면 그대로
    maybe_details = raw.get("details") or _safe_get(raw, "bricks", "details")
    if isinstance(maybe_details, list):
        details_lst = [str(x) for x in maybe_details if x is not None]
    elif isinstance(maybe_details, str):
        details_lst = [maybe_details]

    if score is None:
        dets.append("응답에 score 없음 → 0으로 대체")
        score = 0.0

    if is_anomaly is None:
        # 판단 불가 → False로 보수적 처리 (후속 규칙에서 경고/주의 가능)
        dets.append("응답에 is_anomaly 없음 → False로 대체")
        is_anomaly = False

    return {
        "score": float(score),
        "is_anomaly": bool(is_anomaly),
        "threshold": thr,
        "percentile": pct,
        "model_version": version,
        "details": (details_lst + dets) if dets else details_lst,
    }


# -----------------------------------------------------------------------------
# 3) 브릭스 표준 포스트프로세서
# -----------------------------------------------------------------------------
def _bricks_postprocess(d: Dict[str, Any]) -> Dict[str, Any]:
    """
    입력: {score, is_anomaly, threshold, percentile, model_version, details[]}
    출력(표준):
      {
        status: good|warn|bad|unknown,
        severity: 0..100,
        score, threshold, percentile, is_anomaly, proximity, model_version,
        summary, details[], at
      }
    규칙:
      - is_anomaly=True → status=bad
      - False이면서 score ≥ 0.9*threshold → status=warn
      - 그 외 good
    severity는 proximity(= score/threshold) 기반으로 0~100 스케일.
    threshold가 없으면 proximity는 None (severity는 score 기반 약식).
    """
    score = _to_float(d.get("score")) or 0.0
    thr = _to_float(d.get("threshold"))
    pct = _to_float(d.get("percentile"))
    flag = bool(d.get("is_anomaly"))
    ver = d.get("model_version")
    details = list(d.get("details") or [])

    proximity = None
    if thr and thr > 0:
        proximity = score / thr

    # status 결정
    status = "good"
    if flag:
        status = "bad"
    elif thr is not None and score >= 0.9 * thr:
        status = "warn"

    # severity 산정
    if proximity is not None:
        sev = min(100.0, max(0.0, proximity * 100.0))
    else:
        # threshold 모를 때는 score를 로짓처럼 스케일(완화)
        sev = min(100.0, max(0.0, 10.0 * math.log10(score + 1.0))) if score > 0 else 0.0

    # 상태에 따라 하한/상한 보정
    if status == "bad":
        sev = max(sev, 95.0)
    elif status == "warn":
        sev = max(sev, 60.0)
    else:  # good
        sev = min(sev, 30.0)

    sev = round(sev, 1)

    # summary
    if status == "bad":
        summary = "이상 징후가 임계값을 초과했습니다."
    elif status == "warn":
        summary = "임계값에 근접했습니다. 주의가 필요합니다."
    elif status == "good":
        summary = "정상 범위입니다."
    else:
        summary = "모델 응답 해석 불가."

    if pct is not None and thr is not None:
        details.insert(0, f"임계값(percentile={int(pct)}p) = {thr:.6f}")
    if proximity is not None:
        details.insert(0, f"proximity = score/threshold = {proximity:.3f}")
    details.insert(0, f"score = {score:.6f}")
    if ver:
        details.append(f"model_version = {ver}")

    return {
        "status": status,
        "severity": sev,
        "score": score,
        "threshold": thr,
        "percentile": pct,
        "is_anomaly": flag,
        "proximity": proximity,
        "model_version": ver,
        "summary": summary,
        "details": details,
        "at": _now_iso(),
    }


# -----------------------------------------------------------------------------
# 4) 라우팅
# -----------------------------------------------------------------------------
@app.route("/", methods=["GET"])
def index():
    # 같은 폴더의 index.html 서빙
    return send_from_directory(STATIC_DIR, "index.html")


@app.route("/<path:fname>", methods=["GET"])
def static_files(fname: str):
    # index 외 정적 파일(테스트 용도)
    fpath = os.path.join(STATIC_DIR, fname)
    if os.path.isfile(fpath):
        return send_from_directory(STATIC_DIR, fname)
    return ("Not Found", 404)


@app.route("/analyze", methods=["POST"])
def analyze():
    """
    입력(JSON):
      {
        "features": {...},
        "threshold": 0.123,                # optional
        "threshold_percentile": 98,        # optional
        "model_version": "iforest@v2"      # optional
      }
    출력(JSON):
      { "bricks": { ...표준스키마... } }
    """
    try:
        data = request.get_json(force=True, silent=False) or {}
        features = data.get("features") or {}
        if not isinstance(features, dict):
            return jsonify({"error": "features must be an object"}), 400

        thr = _to_float(data.get("threshold"))
        pct = _to_float(data.get("threshold_percentile"))
        mv = data.get("model_version")

        model_out = _invoke_databricks_model(features, thr, pct, mv)
        bricks = _bricks_postprocess(model_out)

        return jsonify({"bricks": bricks})
    except Exception as e:
        logger.exception("Analyze failed: %s", e)
        return jsonify({
            "bricks": {
                "status": "unknown",
                "severity": 0,
                "summary": "모델 응답 해석 불가.",
                "details": [str(e)],
                "at": _now_iso()
            }
        }), 500


# -----------------------------------------------------------------------------
# 5) 헬스 체크
# -----------------------------------------------------------------------------
@app.route("/healthz", methods=["GET"])
def healthz():
    return jsonify({"ok": True, "at": _now_iso()})


# -----------------------------------------------------------------------------
# 로컬 실행 (gunicorn 환경에선 미사용)
# -----------------------------------------------------------------------------
if __name__ == "__main__":
    # 로컬 테스트시: python app.py
    port = int(os.environ.get("PORT", "5000"))
    app.run(host="0.0.0.0", port=port, debug=True)
