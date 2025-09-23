# app.py
# -*- coding: utf-8 -*-
"""
Project Guardian - Full Web App (Flask)
- 대시보드/상세 뷰 정적 파일 서빙
- Databricks 이상탐지 응답 파서 강화
- threshold / threshold_percentile / model_version 패스스루
- 브릭스 표준 포스트프로세서
- 모델 버전 리스트/앱 설정 API
"""

from __future__ import annotations
import os
import json
import math
import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional, List

import requests
from flask import Flask, jsonify, request, send_from_directory

# -----------------------------------------------------------------------------
# 기본 설정
# -----------------------------------------------------------------------------
ROOT = os.path.dirname(os.path.abspath(__file__))
# 정적 HTML들이 같은 폴더(web 루트)에 있다고 가정 (Azure에서 --chdir web 로 실행)
STATIC_DIR = ROOT

logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO"),
    format="%(asctime)s | %(levelname)s | %(message)s",
)
log = logging.getLogger("guardian")

app = Flask(__name__, static_folder=None)
app.config["JSON_SORT_KEYS"] = False

APP_NAME = os.environ.get("APP_NAME", "Project Guardian")
APP_STAGE = os.environ.get("APP_STAGE", "staging")
APP_BUILD_AT = os.environ.get("APP_BUILD_AT")  # CI가 주입하면 그대로 노출
if not APP_BUILD_AT:
    APP_BUILD_AT = datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")

# 모델 버전 드롭다운 소스 (환경변수 없으면 기본 셋)
DEFAULT_MODEL_VERSIONS = ["iforest@v1", "iforest@v2", "baseline"]
ENV_MODEL_VERSIONS = [
    v.strip() for v in os.environ.get("DATABRICKS_MODEL_VERSIONS", "").split(",") if v.strip()
] or DEFAULT_MODEL_VERSIONS


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
            if isinstance(k, int) and 0 <= k < len(cur):
                cur = cur[k]
            else:
                return default
        else:
            cur = cur.get(k, default)
    return cur


# -----------------------------------------------------------------------------
# Databricks 호출 (없으면 페일세이프)
# -----------------------------------------------------------------------------
def _invoke_databricks_model(
    features: Dict[str, Any],
    threshold: Optional[float],
    threshold_percentile: Optional[float],
    model_version: Optional[str],
) -> Dict[str, Any]:
    """
    반환:
      {
        "raw": {...},
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

    if db_url and db_token:
        try:
            headers = {
                "Authorization": f"Bearer {db_token}",
                "Content-Type": "application/json",
            }
            payload = {
                "features": features,
                "threshold": threshold,
                "threshold_percentile": threshold_percentile,
                "model_version": model_version,
            }
            resp = requests.post(db_url, headers=headers, json=payload, timeout=15)
            resp.raise_for_status()
            raw = resp.json()
            parsed = _extract_anomaly_details(raw)

            # 요청 파라미터 보존(서버가 안주면)
            if threshold is not None and parsed.get("threshold") is None:
                parsed["threshold"] = threshold
            if threshold_percentile is not None and parsed.get("percentile") is None:
                parsed["percentile"] = threshold_percentile
            if model_version and not parsed.get("model_version"):
                parsed["model_version"] = model_version

            parsed["raw"] = raw
            return parsed
        except Exception as e:
            log.exception("Databricks call failed: %s", e)

    # --- Fallback: 팀 규칙 ---
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

    thr = _to_float(threshold)
    pct = _to_float(threshold_percentile)
    if thr is None and pct is not None and score is not None:
        thr = score * (1.05 if pct >= 98 else 1.02)
        dets.append(f"임시 임계값 추정 (percentile={pct})")

    if flag is None and thr is not None:
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
# Databricks 응답 파서
# -----------------------------------------------------------------------------
def _extract_anomaly_details(raw: Dict[str, Any]) -> Dict[str, Any]:
    dets: List[str] = []

    score = _to_float(raw.get("score"))
    is_anomaly = raw.get("is_anomaly")
    thr = _to_float(raw.get("threshold"))
    pct = _to_float(raw.get("percentile") or raw.get("threshold_percentile"))
    version = raw.get("model_version") or raw.get("version")

    if score is None:
        score = (
            _to_float(_safe_get(raw, "data", "score"))
            or _to_float(_safe_get(raw, "prediction", "score"))
            or _to_float(_safe_get(raw, "output", "score"))
            or _to_float(_safe_get(raw, "bricks", "score"))
        )

    if is_anomaly is None:
        is_anomaly = (
            _safe_get(raw, "data", "is_anomaly")
            or _safe_get(raw, "prediction", "is_anomaly")
            or _safe_get(raw, "output", "is_anomaly")
            or _safe_get(raw, "bricks", "is_anomaly")
        )
    if isinstance(is_anomaly, str):
        is_anomaly = is_anomaly.lower() in ("true", "1", "yes")

    if thr is None:
        thr = (
            _to_float(_safe_get(raw, "data", "threshold"))
            or _to_float(_safe_get(raw, "prediction", "threshold"))
            or _to_float(_safe_get(raw, "bricks", "threshold"))
        )
    if pct is None:
        pct = (
            _to_float(_safe_get(raw, "data", "percentile"))
            or _to_float(_safe_get(raw, "prediction", "percentile"))
            or _to_float(_safe_get(raw, "bricks", "percentile"))
        )
    if version is None:
        version = _safe_get(raw, "data", "model_version") or _safe_get(
            raw, "bricks", "model_version"
        )

    details_lst = []
    maybe = raw.get("details") or _safe_get(raw, "bricks", "details")
    if isinstance(maybe, list):
        details_lst = [str(x) for x in maybe if x is not None]
    elif isinstance(maybe, str):
        details_lst = [maybe]

    if score is None:
        dets.append("응답에 score 없음 → 0으로 대체")
        score = 0.0
    if is_anomaly is None:
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
# 브릭스 표준 포스트프로세서
# -----------------------------------------------------------------------------
def _bricks_postprocess(d: Dict[str, Any]) -> Dict[str, Any]:
    score = _to_float(d.get("score")) or 0.0
    thr = _to_float(d.get("threshold"))
    pct = _to_float(d.get("percentile"))
    flag = bool(d.get("is_anomaly"))
    ver = d.get("model_version")
    details = list(d.get("details") or [])

    proximity = None
    if thr and thr > 0:
        proximity = score / thr

    # status
    if flag:
        status = "bad"
    elif thr is not None and score >= 0.9 * thr:
        status = "warn"
    else:
        status = "good"

    # severity
    if proximity is not None:
        sev = min(100.0, max(0.0, proximity * 100.0))
    else:
        sev = min(100.0, max(0.0, 10.0 * math.log10(score + 1.0))) if score > 0 else 0.0

    if status == "bad":
        sev = max(sev, 95.0)
        summary = "이상 징후가 임계값을 초과했습니다."
    elif status == "warn":
        sev = max(sev, 60.0)
        summary = "임계값에 근접했습니다. 주의가 필요합니다."
    else:
        sev = min(sev, 30.0)
        summary = "정상 범위입니다."

    sev = round(sev, 1)

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
# 정적 페이지 라우트 (대시보드/상세/결과/로딩)
# -----------------------------------------------------------------------------
def _serve(fname: str):
    fpath = os.path.join(STATIC_DIR, fname)
    if not os.path.isfile(fpath):
        return ("Not Found", 404)
    return send_from_directory(STATIC_DIR, fname)

@app.route("/", methods=["GET"])
def index():
    return _serve("index.html")

@app.route("/dashboard", methods=["GET"])
def dashboard():
    return _serve("dashboard_branch.html")

@app.route("/detail", methods=["GET"])
def detail():
    return _serve("detail_view.html")

@app.route("/results", methods=["GET"])
def results_page():
    return _serve("results.html")

@app.route("/loading", methods=["GET"])
def loading_page():
    return _serve("loading.html")

@app.route("/<path:fname>", methods=["GET"])
def static_files(fname: str):
    return _serve(fname)


# -----------------------------------------------------------------------------
# API: 분석, 모델 버전, 설정
# -----------------------------------------------------------------------------
@app.route("/analyze", methods=["POST"])
def analyze():
    """
    요청:
      {
        "features": {...},
        "threshold": 0.123,                # optional
        "threshold_percentile": 98,        # optional
        "model_version": "iforest@v2"      # optional
      }
    응답: { "bricks": { status, severity, ... } }
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
        log.exception("Analyze failed: %s", e)
        return jsonify({
            "bricks": {
                "status": "unknown",
                "severity": 0,
                "summary": "모델 응답 해석 불가.",
                "details": [str(e)],
                "at": _now_iso()
            }
        }), 500


@app.route("/api/models/versions", methods=["GET"])
def list_model_versions():
    """
    모델 버전 드롭다운 데이터 제공.
    환경변수 DATABRICKS_MODEL_VERSIONS="a,b,c" 없으면 기본값 사용.
    """
    return jsonify({
        "versions": ENV_MODEL_VERSIONS,
        "default": ENV_MODEL_VERSIONS[0] if ENV_MODEL_VERSIONS else None,
        "at": _now_iso()
    })


@app.route("/api/settings", methods=["GET"])
def api_settings():
    """
    프론트 초기화 공통 설정.
    """
    return jsonify({
        "app": APP_NAME,
        "stage": APP_STAGE,
        "build_at": APP_BUILD_AT,
        "databricks_url_set": bool(os.environ.get("DATABRICKS_MODEL_URL")),
        "model_versions": ENV_MODEL_VERSIONS,
        "health": {"ok": True, "at": _now_iso()},
    })


# -----------------------------------------------------------------------------
# 헬스체크
# -----------------------------------------------------------------------------
@app.route("/healthz", methods=["GET"])
def healthz():
    return jsonify({"ok": True, "at": _now_iso()})


# -----------------------------------------------------------------------------
# 로컬 실행
# -----------------------------------------------------------------------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    app.run(host="0.0.0.0", port=port, debug=True)
