# dags/cve_raw_to_silver_flatten_upsert.py
from __future__ import annotations

from airflow import DAG
from airflow.operators.python import PythonOperator
from airflow.exceptions import AirflowSkipException
from datetime import datetime, timedelta
import os, json, re
from io import BytesIO

import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq

# ---------------------- CONFIG ----------------------
BUCKET        = os.environ.get("S3_BUCKET", "medallion-data-cve")
RAW_PREFIX    = "Raw_Container/cve_parquet"                 # year=YYYY/ingestion_date=YYYY-MM-DD/*.parquet
SILVER_PREFIX = "Silver_Layer/cve_silver"
SILVER_FILE   = f"{SILVER_PREFIX}/cve_silver.parquet"       # single Silver file
PROCESSED     = f"{SILVER_PREFIX}/_processed"               # processed markers
AWS_CONN_ID   = "AWS_DEFAULT"

# ---------------------- S3 HELPERS ----------------------
def _list_common_prefixes(s3, prefix: str):
    c = s3.get_conn(); p = c.get_paginator("list_objects_v2")
    out = []
    for page in p.paginate(Bucket=BUCKET, Prefix=prefix.rstrip('/')+'/', Delimiter='/'):
        for cp in page.get("CommonPrefixes", []):
            out.append(cp["Prefix"])
    return out

def _list_objects(s3, prefix: str):
    c = s3.get_conn(); p = c.get_paginator("list_objects_v2")
    out = []
    for page in p.paginate(Bucket=BUCKET, Prefix=prefix.rstrip('/')+'/'):
        for obj in page.get("Contents", []):
            out.append(obj["Key"])
    return out

def _read_parquet_to_df(s3, key: str) -> pd.DataFrame:
    body = s3.get_key(key, BUCKET).get()["Body"].read()
    tbl = pq.read_table(BytesIO(body))
    df = tbl.to_pandas()
    df.columns = [str(c).strip().lower() for c in df.columns]
    return df

def _write_df_to_parquet(s3, key: str, df: pd.DataFrame):
    """
    IMPORTANT CHANGE:
    - Only coerce _ingest_ts to timestamp.
    - LEAVE date_updated as STRING so Snowflake COPY can parse it reliably.
    """
    if "_ingest_ts" in df.columns:
        df["_ingest_ts"] = (
            pd.to_datetime(df["_ingest_ts"], errors="coerce", utc=True)
              .dt.tz_localize(None)
        )
    # Do NOT touch df["date_updated"] (keep as ISO string / None)

    buf = BytesIO()
    pq.write_table(pa.Table.from_pandas(df, preserve_index=False), buf, compression="snappy")
    buf.seek(0)
    s3.get_conn().put_object(Bucket=BUCKET, Key=key, Body=buf.getvalue(), ContentType="application/x-parquet")

def _put_marker(s3, key: str):
    s3.load_string(string_data="OK", key=key.rstrip('/'), bucket_name=BUCKET, replace=True)

# ---------------------- JSON / CVE HELPERS ----------------------
def _json_loads_safely(raw_text: str):
    """Handle double-encoded JSON gracefully."""
    obj = json.loads(raw_text)
    if isinstance(obj, str):
        obj = json.loads(obj)
    return obj

def _strip_html(text):
    if not text: return None
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", str(text))).strip()

def _pick_first_english(items, value_key="value"):
    if not isinstance(items, list) or not items: return None
    for it in items:
        if (it or {}).get("lang") == "en":
            return (it or {}).get(value_key)
    return (items[0] or {}).get(value_key)

def _gather_all_containers(parsed):
    """Return a flat list of all container dicts (cna, adp, etc.)."""
    cont = parsed.get("containers") or {}
    out = []
    for v in cont.values():
        if isinstance(v, dict): out.append(v)
        elif isinstance(v, list): out.extend([x for x in v if isinstance(x, dict)])
    return out

def _best_title_desc_sol(parsed):
    title = desc = sol = None
    for c in _gather_all_containers(parsed):
        if title is None: title = c.get("title")
        if desc is None:  desc = _pick_first_english(c.get("descriptions", []))
        if sol  is None:  sol  = _pick_first_english(c.get("solutions", []))
        if title and desc and sol: break
    return title, (_strip_html(desc) if desc else "Unknown"), (_strip_html(sol) if sol else "Unknown")

def _choose_cvss(parsed):
    metrics_all = []
    for c in _gather_all_containers(parsed):
        metrics_all.extend(c.get("metrics", []) or [])
    best = None
    for pref in ["cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"]:
        for m in metrics_all:
            obj = (m or {}).get(pref)
            if obj: best = obj; break
        if best: break
    if not best: return None, None
    score = best.get("baseScore")
    sev = best.get("baseSeverity")
    if score is not None and not sev:
        sev = "LOW" if score < 4 else "MEDIUM" if score < 7 else "HIGH" if score < 9 else "CRITICAL"
    return score, sev

def _pick_reference_url(parsed):
    refs = []
    for c in _gather_all_containers(parsed):
        refs.extend(c.get("references", []) or [])
    if not refs: return None
    def rank(ref):
        tags = set((ref or {}).get("tags") or [])
        if "vendor-advisory" in tags: return 0
        if "patch" in tags: return 1
        return 9
    for r in sorted(refs, key=rank):
        if r.get("url"): return r["url"]
    return None

def _latest_version_label(ve):
    if ve.get("lessThanOrEqual"):     return f"≤ {ve['lessThanOrEqual']}"
    if ve.get("lessThan"):            return f"< {ve['lessThan']}"
    if ve.get("greaterThanOrEqual"):  return f"≥ {ve['greaterThanOrEqual']}"
    if ve.get("version"):             return f"v{ve['version']}"
    return None

def _normalize(s: str | None) -> str | None:
    if s is None: return None
    s = s.replace("≤", "<=").replace("–", "-")
    return re.sub(r"\s+", " ", s).strip().lower()

def _collect_all_dateupdated(parsed) -> str | None:
    """
    Pull dateUpdated from top-level cveMetadata and ANY container.providerMetadata.
    Return the latest **ISO string** (keep as text), else None.

    We intentionally avoid pandas here to prevent NaT/NULL surprises.
    ISO-8601 strings with 'Z' sort lexicographically by recency.
    """
    dates: list[str] = []

    # Top-level
    top = (parsed.get("cveMetadata") or {}).get("dateUpdated")
    if top:
        dates.append(str(top))

    # containers.*.providerMetadata.dateUpdated
    for c in _gather_all_containers(parsed):
        prov = (c or {}).get("providerMetadata") or {}
        du = prov.get("dateUpdated")
        if du:
            dates.append(str(du))

    if not dates:
        return None

    return max(dates)  # latest by lexicographic order for Z-terminated ISO strings

# ---------------------- ROW EMISSION ----------------------
def _rows_from_raw(raw_json_text: str, ingest_ts) -> list[dict]:
    """
    Emit ONE ROW per (vendor, product) pair found in each 'affected' entry across all containers.
    Also attach date_updated (latest across sources, kept as ISO string) and a fresh _ingest_ts.
    """
    parsed = _json_loads_safely(raw_json_text)
    cve_id = (parsed.get("cveMetadata", {}).get("cveId") or "").strip().upper()

    # Robust date_updated (keep as string)
    date_updated_iso = _collect_all_dateupdated(parsed)

    # ---------- Optional debug ----------
    if ('"dateUpdated"' in raw_json_text) and (date_updated_iso is None):
        print(f"[DEBUG] {cve_id}: raw has dateUpdated but parser returned None")
    # -----------------------------------

    title, description, solution = _best_title_desc_sol(parsed)
    cvss_score, cvss_severity = _choose_cvss(parsed)
    reference_url = _pick_reference_url(parsed)

    # Ensure missing CVSS => 0.0
    if cvss_score in (None, "", "NaN") or (pd.isna(cvss_score) if cvss_score is not None else True):
        cvss_score = 0.0

    now_utc = pd.Timestamp.utcnow()
    rows, any_found = [], False

    for c in _gather_all_containers(parsed):
        for aff in (c.get("affected", []) or []):
            vendor  = (aff or {}).get("vendor")
            product = (aff or {}).get("product")
            if not vendor and not product:
                continue
            label = None
            for ve in ((aff or {}).get("versions", []) or []):
                label = _latest_version_label(ve or {})
                if label: break
            product_val = product if not label else f"{product} ({label})"
            any_found = True
            rows.append({
                "cve_id": cve_id,
                "vendor_name": vendor,
                "vendor_name_norm": _normalize(vendor) or "unknown",
                "product_name": product_val,
                "product_name_norm": _normalize(product_val) or "unknown",
                "title": title or "Unknown",
                "description": description or "Unknown",
                "solution": solution or "Unknown",
                "cvss_score": cvss_score,
                "cvss_severity": cvss_severity or "Unknown",
                "reference_url": reference_url or "Unknown",
                "date_updated": date_updated_iso,   # keep as string
                "_ingest_ts": now_utc,              # real timestamp
            })

    if not any_found:
        rows.append({
            "cve_id": cve_id,
            "vendor_name": "Unknown",
            "vendor_name_norm": "unknown",
            "product_name": "Unknown",
            "product_name_norm": "unknown",
            "title": title or "Unknown",
            "description": description or "Unknown",
            "solution": solution or "Unknown",
            "cvss_score": cvss_score,
            "cvss_severity": cvss_severity or "Unknown",
            "reference_url": reference_url or "Unknown",
            "date_updated": date_updated_iso,       # keep as string
            "_ingest_ts": now_utc,
        })
    return rows

# ---------------------- FILLER STANDARDIZATION ----------------------
def _fill_unknown_strings(df: pd.DataFrame) -> pd.DataFrame:
    if df.empty: return df
    obj_cols = df.select_dtypes(include=["object"]).columns
    if not len(obj_cols): return df

    blank_re = r"^\s*$"
    filler_full_re = (
        r"(?i)^\s*(?:v+)?\s*(?:n/?a|na|none|null|unknown)\s*"
        r"(?:\(\s*(?:v+)?\s*(?:n/?a|na|none|null|unknown)\s*\))?\s*$"
    )
    unknown_typos_re = r"(?i)^\s*(?:unkown|uknown)\s*$"

    for col in obj_cols:
        target = "unknown" if col.endswith("_norm") else "Unknown"
        df[col] = df[col].fillna(target)
        df[col] = df[col].replace(blank_re, target, regex=True)
        df[col] = df[col].replace(filler_full_re, target, regex=True)
        df[col] = df[col].replace(unknown_typos_re, target, regex=True)
        df[col] = df[col].replace(r"(?i)^\s*unknown\s*$", target, regex=True)
        df[col] = df[col].astype(str).str.strip()
    return df

# ---------------------- CORE PROCESSING ----------------------
def _process_partition(s3, partition_prefix: str) -> bool:
    raw_files = [k for k in _list_objects(s3, partition_prefix) if k.lower().endswith((".parquet", ".parq"))]
    if not raw_files: return False

    batch_rows = []
    for key in raw_files:
        df = _read_parquet_to_df(s3, key)
        raw_col = "raw_data" if "raw_data" in df.columns else ("raw" if "raw" in df.columns else None)
        ts_col  = "timestamp" if "timestamp" in df.columns else ("ingest_ts" if "ingest_ts" in df.columns else None)
        if not raw_col: continue

        for _, r in df.iterrows():
            ingest_ts = pd.to_datetime(r.get(ts_col), errors="coerce") if ts_col else pd.NaT
            batch_rows.extend(_rows_from_raw(r[raw_col], ingest_ts))

    if not batch_rows: return False

    df_new = _fill_unknown_strings(pd.DataFrame(batch_rows))

    try:
        df_silver = _read_parquet_to_df(s3, SILVER_FILE)
    except Exception:
        df_silver = pd.DataFrame(columns=df_new.columns)

    key_cols = ["cve_id", "vendor_name_norm", "product_name_norm"]
    df_all = pd.concat([df_silver, df_new], ignore_index=True)

    if "_ingest_ts" not in df_all.columns:
        df_all["_ingest_ts"] = pd.NaT
    df_all["_ingest_ts"] = pd.to_datetime(df_all["_ingest_ts"], errors="coerce")

    df_all = df_all.sort_values("_ingest_ts").drop_duplicates(subset=key_cols, keep="last").reset_index(drop=True)
    df_all = _fill_unknown_strings(df_all)

    _write_df_to_parquet(s3, SILVER_FILE, df_all)
    _put_marker(s3, f"{PROCESSED}/{partition_prefix.strip('/')}/_DONE")
    return True

def transform_raw_to_silver_incremental():
    from airflow.providers.amazon.aws.hooks.s3 import S3Hook
    s3 = S3Hook(aws_conn_id=AWS_CONN_ID)
    processed_any = False

    for yp in _list_common_prefixes(s3, RAW_PREFIX):
        keys = _list_objects(s3, yp)
        idate_prefixes = sorted({"/".join(k.split("/")[:4]) + "/" for k in keys if "ingestion_date=" in k})
        for ip in idate_prefixes:
            marker = f"{PROCESSED}/{ip.strip('/')}/_DONE"
            if s3.check_for_key(marker, bucket_name=BUCKET):
                continue
            if _process_partition(s3, ip):
                processed_any = True

    if not processed_any:
        raise AirflowSkipException("No new parquet partitions found.")

# ---------------------- DAG ----------------------
with DAG(
    dag_id="cve_raw_to_silver_flatten_upsert",
    description="Unified Silver: one row per CVE × (vendor, product); incremental upsert; Unknown standardization; robust dateUpdated",
    start_date=datetime(2025, 10, 15),
    schedule="@once",
    catchup=False,
    max_active_runs=1,
    dagrun_timeout=timedelta(hours=6),
    tags=["cve", "silver", "vendor-product", "explode", "upsert", "s3"],
) as dag:
    PythonOperator(
        task_id="transform_raw_to_silver_incremental",
        python_callable=transform_raw_to_silver_incremental,
        execution_timeout=timedelta(hours=5),
    )
