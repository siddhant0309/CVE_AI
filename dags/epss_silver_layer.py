# dags/epss_raw_to_silver_flatten.py
from __future__ import annotations

from airflow import DAG
from airflow.operators.python import PythonOperator
from airflow.exceptions import AirflowSkipException
from datetime import datetime, timedelta
import os, json, hashlib
from io import BytesIO

# ---------------------- CONFIG ----------------------
BUCKET = os.environ.get("S3_BUCKET", "medallion-data-cve")
RAW_PREFIX = "Raw_Container"
SILVER_PREFIX = "Silver_Layer/epss_silver"
SILVER_CANONICAL = f"{SILVER_PREFIX}/epss_silver.parquet"
SILVER_VERSIONS_DIR = f"{SILVER_PREFIX}/versions"
PROCESSED_MARKERS = f"{SILVER_PREFIX}/_processed"
AWS_CONN_ID = "AWS_DEFAULT"

# ---------------------- S3 HELPERS ----------------------
def _list_objects(s3, prefix: str):
    client = s3.get_conn()
    paginator = client.get_paginator("list_objects_v2")
    return [obj["Key"] for page in paginator.paginate(Bucket=BUCKET, Prefix=prefix.rstrip('/')+'/') 
            for obj in page.get("Contents", [])]

def _read_parquet_to_df(s3, key: str):
    import pyarrow.parquet as pq
    body = s3.get_key(key, BUCKET).get()["Body"].read()
    df = pq.read_table(BytesIO(body)).to_pandas()
    df.columns = [str(c).strip().lower() for c in df.columns]
    return df

def _write_df_to_parquet(s3, key: str, df):
    import pyarrow as pa
    import pyarrow.parquet as pq
    buf = BytesIO()
    pq.write_table(pa.Table.from_pandas(df, preserve_index=False), buf, compression="snappy")
    buf.seek(0)
    s3.get_conn().put_object(Bucket=BUCKET, Key=key, Body=buf.getvalue(), ContentType="application/x-parquet")

def _put_marker(s3, key: str):
    s3.load_string(string_data="OK", key=key, bucket_name=BUCKET, replace=True)

# ---------------------- EPSS PROCESSING ----------------------
def _flatten_epss_payload(raw_json_text: str):
    """Parse EPSS JSON array and return list of dicts with cve_id, epss, percentile"""
    try:
        parsed = json.loads(raw_json_text or "[]")
    except Exception:
        return []
    
    out = []
    for item in parsed or []:
        cve = (item or {}).get("cve")
        if cve:
            out.append({
                "cve_id": str(cve).strip().upper(),
                "epss": float(item.get("epss")) if item.get("epss") is not None else None,
                "percentile": float(item.get("percentile")) if item.get("percentile") is not None else None,
            })
    return out

def _find_column(df, *candidates):
    """Find first matching column name from candidates (case-insensitive)"""
    for col in candidates:
        if col in df.columns:
            return col
    return None

def _process_one_raw_key(s3, key: str):
    import pandas as pd

    df_raw = _read_parquet_to_df(s3, key)
    print(f"[DEBUG] Processing {key}: {len(df_raw)} rows, columns: {list(df_raw.columns)}")

    raw_col = _find_column(df_raw, "raw_data")
    ts_col = _find_column(df_raw, "timestamp_ntz", "timestamp")
    hash_col = _find_column(df_raw, "data_hash")

    if not raw_col:
        print("[WARN] No raw_data column found; skipping.")
        return None, None, None

    new_rows = []
    latest_ts = pd.NaT
    
    for _, r in df_raw.iterrows():
        rows = _flatten_epss_payload(r[raw_col])
        ts_val = pd.to_datetime(r[ts_col], errors="coerce") if ts_col else pd.NaT
        
        if pd.notna(ts_val) and (pd.isna(latest_ts) or ts_val > latest_ts):
            latest_ts = ts_val
        
        for d in rows:
            d["_ingest_ts"] = ts_val
            new_rows.append(d)

    if not new_rows:
        print("[DEBUG] No EPSS rows extracted.")
        return None, None, None

    # Generate fingerprint for processed marker
    fp = (str(df_raw.at[0, hash_col]) if hash_col and pd.notna(df_raw.at[0, hash_col]) 
          else hashlib.sha256(str(df_raw.at[0, raw_col]).encode("utf-8")).hexdigest())
    
    marker_key = f"{PROCESSED_MARKERS}/by_raw_key/{fp}/_DONE"
    df_new = pd.DataFrame(new_rows, columns=["cve_id","epss","percentile","_ingest_ts"])
    
    return df_new, latest_ts, marker_key

# ---------------------- MAIN TRANSFORM ----------------------
def transform_epss_raw_to_silver():
    from airflow.providers.amazon.aws.hooks.s3 import S3Hook
    import pandas as pd

    print(f"[DEBUG] BUCKET={BUCKET}, RAW_PREFIX={RAW_PREFIX}, SILVER_PREFIX={SILVER_PREFIX}")
    s3 = S3Hook(aws_conn_id=AWS_CONN_ID)

    # Find EPSS parquet files
    all_keys = _list_objects(s3, RAW_PREFIX)
    raw_keys = [k for k in all_keys if k.lower().endswith((".parquet", ".parq")) and "epss" in k.lower()]
    print(f"[DEBUG] Found {len(raw_keys)} EPSS parquet files: {raw_keys}")

    if not raw_keys:
        raise AirflowSkipException("No EPSS parquet files found.")

    # Load existing canonical silver
    try:
        df_merged = _read_parquet_to_df(s3, SILVER_CANONICAL)
    except Exception:
        df_merged = pd.DataFrame(columns=["cve_id","epss","percentile","_ingest_ts"])

    processed_any = False
    max_new_ts = None

    for key in raw_keys:
        df_new, latest_ts, marker_key = _process_one_raw_key(s3, key)
        
        if df_new is None or df_new.empty:
            continue

        # Skip if already processed
        if _list_objects(s3, marker_key):
            print(f"[DEBUG] Already processed: {key}")
            continue

        # Merge and dedupe by cve_id (keep latest by _ingest_ts)
        df_merged = pd.concat([df_merged, df_new], ignore_index=True)
        df_merged = df_merged.sort_values("_ingest_ts").drop_duplicates(subset=["cve_id"], keep="last").reset_index(drop=True)

        # Track max timestamp
        if latest_ts and (max_new_ts is None or latest_ts > max_new_ts):
            max_new_ts = latest_ts

        # Mark as processed
        _put_marker(s3, marker_key)
        processed_any = True
        print(f"[DEBUG] Processed and marked: {key}")

    if not processed_any:
        raise AirflowSkipException("Nothing new to process (all files already marked).")

    # Write canonical silver
    print(f"[DEBUG] Writing canonical: {SILVER_CANONICAL} ({len(df_merged)} rows)")
    _write_df_to_parquet(s3, SILVER_CANONICAL, df_merged)

    # Write timestamped version
    ts_for_name = (max_new_ts if max_new_ts else pd.Timestamp.utcnow()).strftime("%Y%m%d%H%M%S")
    version_key = f"{SILVER_VERSIONS_DIR}/epss_silver_{ts_for_name}.parquet"
    print(f"[DEBUG] Writing versioned: {version_key}")
    _write_df_to_parquet(s3, version_key, df_merged)

# ---------------------- DAG ----------------------
with DAG(
    dag_id="epss_raw_to_silver_flatten",
    description="Parse EPSS JSON from Raw parquet into Silver (cve_id, epss, percentile); non-partitioned with versioned copies.",
    start_date=datetime(2025, 10, 15),
    schedule="@once",
    catchup=False,
    max_active_runs=1,
    dagrun_timeout=timedelta(hours=1),
    tags=["epss","silver","flatten","s3"],
) as dag:
    PythonOperator(
        task_id="transform_epss_raw_to_silver",
        python_callable=transform_epss_raw_to_silver,
        execution_timeout=timedelta(minutes=30),
    )