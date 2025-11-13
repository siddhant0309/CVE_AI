from airflow import DAG
from airflow.operators.python import PythonOperator
from airflow.providers.amazon.aws.hooks.s3 import S3Hook
from datetime import datetime
import pandas as pd
import json
import re
import ast
from io import StringIO

# --- Config ---
BUCKET_NAME = "medallion-data-cve"
SRC_KEY = "Raw_Container/kev_data_master.csv"           # input master file
DEST_FILENAME = "kev_flattened_latest_clean.csv"        # output filename in Silver

def _silver_key_from_src(src_key: str, dest_filename: str) -> str:
    rest = src_key.split("/", 1)[1] if "/" in src_key else ""
    dir_part = rest.rsplit("/", 1)[0] if "/" in rest else ""
    return f"Silver_Layer/{dir_part}/{dest_filename}" if dir_part else f"Silver_Layer/{dest_filename}"

def _normalize_whitespace(s: str | None) -> str | None:
    if s is None or (isinstance(s, float) and pd.isna(s)):
        return None
    return re.sub(r"\s+", " ", str(s)).strip()

def _clean_cwes(val) -> str | None:
    if val is None or (isinstance(val, float) and pd.isna(val)):
        return None
    if isinstance(val, (list, tuple)):
        return ", ".join(str(x) for x in val if pd.notna(x) and str(x).strip() != "") or None

    s = str(val).strip()
    if s == "" or s.upper() == "NULL":
        return None
    try:
        parsed = ast.literal_eval(s)
        if isinstance(parsed, (list, tuple)):
            return ", ".join(str(x) for x in parsed if pd.notna(x) and str(x).strip() != "") or None
    except Exception:
        pass

    s = re.sub(r'[\[\]\"]', "", s)   # remove [ ] "
    s = s.replace("'", "")           # remove '
    s = re.sub(r"\s*,\s*", ", ", s)  # tidy commas
    s = re.sub(r"\s+", " ", s).strip()
    return s or None

def flatten_and_clean_kev():
    s3 = S3Hook(aws_conn_id="AWS_DEFAULT")

    # --- Read latest master CSV from Raw container ---
    csv_text = s3.read_key(key=SRC_KEY, bucket_name=BUCKET_NAME)
    master = pd.read_csv(StringIO(csv_text))

    master["timestamp"] = pd.to_datetime(master["timestamp"], errors="coerce")
    if master["timestamp"].isna().all():
        raise ValueError("All 'timestamp' values are NaT after parsing—check source timestamp format.")
    latest_row = master.loc[master["timestamp"].idxmax()]

    # --- Flatten the JSON payload ---
    raw_json = json.loads(latest_row["raw_data"])
    vulnerabilities = raw_json.get("vulnerabilities", []) or []
    flat = pd.json_normalize(vulnerabilities)

    col_map = {
        "cveID": "cveID",
        "vendorProject": "vendorProject",
        "product": "product",
        "vulnerabilityName": "vulnerabilityName",
        "dateAdded": "dateAdded",
        "shortDescription": "shortDescription",
        "requiredAction": "requiredAction",
        "dueDate": "dueDate",
        "knownRansomwareCampaignUse": "knownRansomwareCampaignUse",
        "notes": "notes",
        "cwes": "cwes",
    }
    existing_cols = {k: v for k, v in col_map.items() if k in flat.columns}
    flat = flat[list(existing_cols.keys())].rename(columns=existing_cols)

    # --- Cleaning ---
    if "cwes" in flat.columns:
        flat["cwes"] = flat["cwes"].apply(_clean_cwes)
        # fill missing CWEs with "Unknown"
        flat["cwes"] = flat["cwes"].replace({"": None, "NULL": None}).fillna("Unknown")

    for txt_col in ("shortDescription", "requiredAction", "notes"):
        if txt_col in flat.columns:
            flat[txt_col] = flat[txt_col].apply(_normalize_whitespace)


    # --- Write to Silver layer in S3 ---
    dest_key = _silver_key_from_src(SRC_KEY, DEST_FILENAME)
    buf = StringIO()
    flat.to_csv(buf, index=False)
    s3.load_string(string_data=buf.getvalue(),
                   key=dest_key,
                   bucket_name=BUCKET_NAME,
                   replace=True)

    print(f"Uploaded cleaned flattened CSV to s3://{BUCKET_NAME}/{dest_key}")
    print(f"Latest snapshot timestamp: {latest_row['timestamp']}")
    print(f"Total rows written: {len(flat)}")

with DAG(
    "kev_flatten_and_clean_to_silver",
    description="Flatten latest KEV snapshot, clean columns, write to S3 Silver layer",
    start_date=datetime(2025, 10, 15),
    schedule=None,           # Airflow 2.6+: use 'schedule=None'
    catchup=False,
    tags=["kev", "flatten", "clean", "silver"],
) as dag:
    PythonOperator(
        task_id="flatten_and_clean_kev",
        python_callable=flatten_and_clean_kev,
    )
