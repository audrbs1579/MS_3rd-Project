
# -*- coding: utf-8 -*-
"""
common.py - Shared utilities for the GHArchive anomaly detection basemodel.
Designed for local VSCode use on Windows paths. Tested with Python 3.10+.

Dependencies (install locally):
    pip install requests pandas numpy python-dateutil tqdm scikit-learn joblib pyarrow fastparquet torch

Notes:
- Uses tqdm with ncols=30 for compact progress bars.
- Saves artifacts under the user-specified base directory.
"""

from __future__ import annotations
import os, re, json, math, gzip, time, hashlib, io, glob
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, Iterable, List, Optional, Tuple

import requests
import pandas as pd
import numpy as np
from dateutil import tz
from tqdm import tqdm

from sklearn.preprocessing import RobustScaler, MinMaxScaler
from sklearn.model_selection import train_test_split
from joblib import dump, load

# -------------------------------
# Paths & general utilities
# -------------------------------

def to_windows_path(p: str) -> str:
    return p.replace("/", "\\")

def ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)

def get_paths(base_dir: str) -> Dict[str, str]:
    """
    Returns standardized project paths rooted at base_dir.
    """
    paths = {
        "base": base_dir,
        "data_train_raw": os.path.join(base_dir, "data", "train", "raw"),
        "data_test_raw": os.path.join(base_dir, "data", "test", "raw"),
        "data_train_feat": os.path.join(base_dir, "data", "train"),
        "data_test_feat": os.path.join(base_dir, "data", "test"),
        "model_dir": os.path.join(base_dir, "model"),
        "ckpt_dir": os.path.join(base_dir, "model", "checkpoints"),
    }
    for p in paths.values():
        ensure_dir(p)
    return paths

# -------------------------------
# GH Archive download helpers
# -------------------------------

def hour_urls(start_utc: datetime, end_utc: datetime) -> Iterable[Tuple[datetime, str]]:
    """
    Yield (hour, url) for GHArchive in [start_utc, end_utc], inclusive of hours.
    URL pattern: https://data.gharchive.org/YYYY-MM-DD-H.json.gz
    """
    assert start_utc.tzinfo is not None and end_utc.tzinfo is not None, "Use timezone-aware datetimes (UTC)."
    cur = start_utc.replace(minute=0, second=0, microsecond=0)
    end = end_utc.replace(minute=0, second=0, microsecond=0)
    while cur <= end:
        url = f"https://data.gharchive.org/{cur.strftime('%Y-%m-%d')}-{cur.hour}.json.gz"
        yield cur, url
        cur += timedelta(hours=1)

def download_one(url: str, out_path: str, timeout: int = 60) -> bool:
    """
    Download a single GHArchive hour file to out_path.
    Returns True if saved, False if skipped/failed.
    """
    if os.path.exists(out_path) and os.path.getsize(out_path) > 0:
        return False  # already exists
    
    try:
        with requests.get(url, stream=True, timeout=timeout) as r:
            r.raise_for_status()
            total = int(r.headers.get("Content-Length", 0)) or None
            chunk = 8192
            with open(out_path, "wb") as f, tqdm(total=total, unit="B", unit_scale=True, ncols=30, desc="download") as bar:
                for c in r.iter_content(chunk_size=chunk):
                    if c:
                        f.write(c)
                        if total:
                            bar.update(len(c))
        return True
    except Exception as e:
        # Save marker file for visibility and move on
        with open(out_path + ".ERR.txt", "w", encoding="utf-8") as ef:
            ef.write(f"Failed to download {url}\n{repr(e)}\n")
        return False

# -------------------------------
# Event parsing / feature extraction
# -------------------------------

EVENT_TYPES = [
    "PushEvent", "PullRequestEvent", "IssuesEvent", "IssueCommentEvent",
    "PullRequestReviewEvent", "CreateEvent", "DeleteEvent", "ReleaseEvent",
]

ACTION_BUCKETS = [
    "opened", "closed", "merged", "reopened", "created", "deleted", "edited", "synchronize", "review_requested"
]

def _hash_bucket(s: Optional[str], buckets: int = 1024) -> int:
    if not s:
        return 0
    h = int(hashlib.md5(s.encode("utf-8")).hexdigest(), 16)
    return h % buckets

def parse_json_gz(path: str) -> Iterable[Dict[str, Any]]:
    with gzip.open(path, "rt", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue

def extract_features_from_event(evt: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Returns a flat feature dict per event, or None if not usable.
    """
    et = evt.get("type")
    if et not in EVENT_TYPES:
        return None

    created_at = evt.get("created_at")
    try:
        dt = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
    except Exception:
        return None

    repo = (evt.get("repo") or {}).get("name")
    actor = (evt.get("actor") or {}).get("login")
    org = None
    if repo and "/" in repo:
        org = repo.split("/")[0]

    # Basic time features
    hour = dt.hour
    dow = dt.weekday()  # 0=Mon
    is_weekend = 1 if dow >= 5 else 0

    f: Dict[str, Any] = {
        "event_type": et,
        "repo": repo or "",
        "org": org or "",
        "actor_login_bucket": _hash_bucket(actor, 1024),
        "repo_bucket": _hash_bucket(repo, 4096),
        "org_bucket": _hash_bucket(org, 1024),
        "hour_of_day": hour,
        "day_of_week": dow,
        "is_weekend": is_weekend,
        "actor_login_len": len(actor or ""),
        "repo_name_len": len(repo or ""),
    }

    payload = evt.get("payload") or {}

    if et == "PushEvent":
        f["push_size"] = payload.get("size", 0)
        f["push_distinct_size"] = payload.get("distinct_size", 0)
        commits = payload.get("commits") or []
        f["num_commits"] = len(commits)
        # rough heuristic for force push: compare size and distinct size
        f["is_force_push_proxy"] = 1 if f["push_size"] > 0 and f["push_distinct_size"] == 0 else 0
        msg_lens = [len((c or {}).get("message") or "") for c in commits] if commits else []
        f["avg_commit_msg_len"] = float(np.mean(msg_lens)) if msg_lens else 0.0

    elif et == "PullRequestEvent":
        pr = (payload.get("pull_request") or {})
        f["pr_action"] = payload.get("action") or ""
        f["pr_merged"] = 1 if pr.get("merged") else 0
        f["pr_additions"] = pr.get("additions", 0) or 0
        f["pr_deletions"] = pr.get("deletions", 0) or 0
        f["pr_changed_files"] = pr.get("changed_files", 0) or 0
        f["pr_title_len"] = len(pr.get("title") or "")
        f["pr_body_len"] = len(pr.get("body") or "")

    elif et == "IssuesEvent":
        f["issue_action"] = payload.get("action") or ""
        issue = payload.get("issue") or {}
        f["issue_title_len"] = len(issue.get("title") or "")
        f["issue_body_len"] = len(issue.get("body") or "")

    elif et == "IssueCommentEvent":
        comment = payload.get("comment") or {}
        f["comment_body_len"] = len(comment.get("body") or "")

    elif et == "PullRequestReviewEvent":
        review = payload.get("review") or {}
        f["review_body_len"] = len(review.get("body") or "")
        f["review_state"] = review.get("state") or ""

    elif et in ("CreateEvent", "DeleteEvent", "ReleaseEvent"):
        f["simple_action"] = payload.get("action") or ""

    return f

def build_dataframe(feature_dicts: Iterable[Dict[str, Any]]) -> pd.DataFrame:
    rows: List[Dict[str, Any]] = []
    for fd in feature_dicts:
        if fd is not None:
            rows.append(fd)
    if not rows:
        return pd.DataFrame()

    df = pd.DataFrame(rows)

    # Categorical -> one-hot
    # Keep human-readable columns for tracing, but bucketed columns are numeric already.
    cats = []
    if "event_type" in df: cats.append("event_type")
    if "pr_action" in df: cats.append("pr_action")
    if "issue_action" in df: cats.append("issue_action")
    if "review_state" in df: cats.append("review_state")
    if "simple_action" in df: cats.append("simple_action")

    df = pd.get_dummies(df, columns=cats, dummy_na=True, dtype=int)

    # Drop raw string cols (repo, org) to avoid high-cardinality leakage
    drop_cols = ["repo", "org"]
    for c in drop_cols:
        if c in df.columns:
            df.drop(columns=[c], inplace=True)

    # Fill NaNs
    df = df.fillna(0)

    # Reorder columns for stability
    df = df.reindex(sorted(df.columns), axis=1)

    return df

def scale_and_save(df: pd.DataFrame, scaler_dir: str, tag: str) -> Tuple[np.ndarray, RobustScaler, MinMaxScaler, List[str]]:
    """
    RobustScaler -> MinMaxScaler [0,1] as described.
    Saves scalers to disk under scaler_dir with names including `tag`.
    """
    ensure_dir(scaler_dir)
    cols = list(df.columns)
    X = df.values.astype(np.float32)

    robust = RobustScaler()
    Xr = robust.fit_transform(X)

    mm = MinMaxScaler()
    Xs = mm.fit_transform(Xr)

    dump(robust, os.path.join(scaler_dir, f"robust_{tag}.joblib"))
    dump(mm, os.path.join(scaler_dir, f"minmax_{tag}.joblib"))
    with open(os.path.join(scaler_dir, f"features_{tag}.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(cols))

    return Xs.astype(np.float32), robust, mm, cols

def load_scalers(scaler_dir: str, tag: str) -> Tuple[RobustScaler, MinMaxScaler, List[str]]:
    robust = load(os.path.join(scaler_dir, f"robust_{tag}.joblib"))
    mm = load(os.path.join(scaler_dir, f"minmax_{tag}.joblib"))
    with open(os.path.join(scaler_dir, f"features_{tag}.txt"), "r", encoding="utf-8") as f:
        cols = [line.strip() for line in f if line.strip()]
    return robust, mm, cols

# -------------------------------
# PyTorch Autoencoder
# -------------------------------

import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset

class AE(nn.Module):
    def __init__(self, in_dim: int, latent: int = 32):
        super().__init__()
        self.encoder = nn.Sequential(
            nn.Linear(in_dim, 256),
            nn.ReLU(),
            nn.Linear(256, 128),
            nn.ReLU(),
            nn.Linear(128, latent),
        )
        self.decoder = nn.Sequential(
            nn.Linear(latent, 128),
            nn.ReLU(),
            nn.Linear(128, 256),
            nn.ReLU(),
            nn.Linear(256, in_dim),
            nn.Sigmoid(),  # data scaled to [0,1]
        )

    def forward(self, x):
        z = self.encoder(x)
        x_hat = self.decoder(z)
        return x_hat

def train_autoencoder(
    X: np.ndarray,
    model_dir: str,
    ckpt_dir: str,
    epochs: int = 20,
    batch_size: int = 1024,
    lr: float = 1e-3,
    val_ratio: float = 0.1,
    seed: int = 42,
    tqdm_ncols: int = 30,
) -> Tuple[str, str]:
    """
    Train an autoencoder with checkpoints and save the best model.
    Returns (best_model_path, last_checkpoint_path).
    """
    torch.manual_seed(seed)
    np.random.seed(seed)

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    in_dim = X.shape[1]
    model = AE(in_dim).to(device)
    opt = torch.optim.Adam(model.parameters(), lr=lr)
    crit = nn.MSELoss()

    X_train, X_val = train_test_split(X, test_size=val_ratio, random_state=seed, shuffle=True)

    tr_ds = TensorDataset(torch.from_numpy(X_train))
    va_ds = TensorDataset(torch.from_numpy(X_val))
    tr_ld = DataLoader(tr_ds, batch_size=batch_size, shuffle=True, drop_last=False)
    va_ld = DataLoader(va_ds, batch_size=batch_size, shuffle=False, drop_last=False)

    best_val = float("inf")
    best_path = os.path.join(model_dir, "base_autoencoder.pt")
    last_ckpt = os.path.join(ckpt_dir, "last.ckpt")

    for ep in range(1, epochs + 1):
        model.train()
        ep_loss = 0.0
        for (xb,) in tqdm(tr_ld, ncols=tqdm_ncols, desc=f"train[{ep}/{epochs}]"):
            xb = xb.to(device)
            opt.zero_grad()
            out = model(xb)
            loss = crit(out, xb)
            loss.backward()
            opt.step()
            ep_loss += loss.item() * xb.size(0)
        ep_loss /= len(tr_ds)

        # val
        model.eval()
        val_loss = 0.0
        with torch.no_grad():
            for (xb,) in tqdm(va_ld, ncols=tqdm_ncols, desc=f"valid[{ep}/{epochs}]"):
                xb = xb.to(device)
                out = model(xb)
                loss = crit(out, xb)
                val_loss += loss.item() * xb.size(0)
        val_loss /= len(va_ds)

        # Save checkpoint
        ensure_dir(ckpt_dir)
        torch.save({"epoch": ep, "state_dict": model.state_dict(), "val_loss": val_loss}, last_ckpt)
        if val_loss < best_val:
            best_val = val_loss
            torch.save(model.state_dict(), best_path)

    return best_path, last_ckpt

def score_anomaly(model_path: str, X: np.ndarray, tqdm_ncols: int = 30) -> np.ndarray:
    """
    Load model and compute reconstruction MSE per row.
    """
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    # Infer input dim from X
    model = AE(in_dim=X.shape[1]).to(device)
    sd = torch.load(model_path, map_location=device)
    model.load_state_dict(sd)
    model.eval()

    ds = TensorDataset(torch.from_numpy(X))
    ld = DataLoader(ds, batch_size=2048, shuffle=False)
    errs = []
    crit = nn.MSELoss(reduction="none")
    with torch.no_grad():
        for (xb,) in tqdm(ld, ncols=tqdm_ncols, desc="score"):
            xb = xb.to(device)
            xh = model(xb)
            mse = crit(xh, xb).mean(dim=1)
            errs.extend(mse.cpu().numpy().tolist())
    return np.array(errs, dtype=np.float32)

# common.py 파일 하단에 다음 함수 추가

def transform_with_scalers(df: pd.DataFrame, scaler_dir: str, tag: str) -> Tuple[np.ndarray, List[str]]:
    """
    Loads pre-trained scalers and uses them to transform new data.
    """
    if not os.path.exists(os.path.join(scaler_dir, f"robust_{tag}.joblib")):
        raise FileNotFoundError(f"Scaler files with tag '{tag}' not found in {scaler_dir}")
        
    robust, mm, cols = load_scalers(scaler_dir, tag)
    
    # 중요: 학습 데이터의 컬럼 순서와 동일하게 맞춰줌
    # 새로운 데이터에 없는 컬럼은 0으로 채움
    df_aligned = df.reindex(columns=cols, fill_value=0)
    
    # reindex 후 컬럼 순서가 바뀔 수 있으므로 다시 정렬
    df_aligned = df_aligned[cols]

    X = df_aligned.values.astype(np.float32)

    # fit_transform이 아닌 transform 사용
    Xr = robust.transform(X)
    Xs = mm.transform(Xr)

    return Xs.astype(np.float32), cols
