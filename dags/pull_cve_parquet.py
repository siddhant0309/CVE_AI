# dags/cvelist_incremental_to_s3_parquet_partitioned_by_year.py
from airflow import DAG
from airflow.operators.python import PythonOperator
from airflow.providers.amazon.aws.hooks.s3 import S3Hook
from airflow.models import Variable
from datetime import datetime, timedelta
import os, json, hashlib, requests
import pandas as pd
import subprocess, tempfile, pathlib
from io import BytesIO
import pyarrow as pa
import pyarrow.parquet as pq

# ======= Repo / Scope =======
OWNER = "CVEProject"
REPO = "cvelistV5"
BRANCH = "main"
YEARS = {"2024", "2025"}
ROOT_PREFIX = "cves/"

# ======= S3 targets (partitioned sink) =======
BUCKET = os.environ.get("S3_BUCKET", "medallion-data-cve")
DATA_PREFIX = os.environ.get("S3_PREFIX", "Raw_Container/cve_parquet")  # partition root

# Checkpoint SHA
STATE_BUCKET = BUCKET
STATE_KEY    = "Raw_Container/state/cvelistV5_last_sha.txt"

def _gh_headers():
    token = os.environ.get("GITHUB_TOKEN") or Variable.get("GITHUB_TOKEN", default_var=None)
    h = {"Accept": "application/vnd.github+json"}
    if token:
        h["Authorization"] = f"Bearer {token}"
    return h

def _list_paths_via_sparse_clone():
    repo_url = "https://github.com/CVEProject/cvelistV5.git"
    wanted = []
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = pathlib.Path(tmp)
        subprocess.run(["git", "init"], cwd=tmp, check=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        subprocess.run(["git", "remote", "add", "origin", repo_url], cwd=tmp, check=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        subprocess.run(["git", "config", "core.sparseCheckout", "true"], cwd=tmp, check=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        (tmp_path / ".git" / "info").mkdir(parents=True, exist_ok=True)
        (tmp_path / ".git" / "info" / "sparse-checkout").write_text("cves/2024/\ncves/2025/\n", encoding="utf-8")
        subprocess.run(["git", "pull", "--depth=1", "origin", "main"], cwd=tmp, check=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        base = tmp_path
        for year in YEARS:
            root = base / "cves" / year
            if not root.exists():
                continue
            for p in root.rglob("*.json"):
                wanted.append(p.relative_to(base).as_posix())
    return wanted

def _read_text_from_s3(s3: S3Hook, bucket: str, key: str):
    try:
        return s3.read_key(key=key, bucket_name=bucket).strip()
    except Exception:
        return None

def _write_text_to_s3(s3: S3Hook, bucket: str, key: str, text: str):
    s3.load_string(string_data=text, key=key, bucket_name=bucket, replace=True)

def _get_head_sha():
    url = f"https://api.github.com/repos/{OWNER}/{REPO}/commits/{BRANCH}"
    r = requests.get(url, headers=_gh_headers(), timeout=60)
    r.raise_for_status()
    return r.json()["sha"]

def _compare_commits(base_sha: str, head_sha: str):
    url = f"https://api.github.com/repos/{OWNER}/{REPO}/compare/{base_sha}...{head_sha}"
    r = requests.get(url, headers=_gh_headers(), timeout=120)
    r.raise_for_status()
    return r.json()

def _filter_cve_paths(files_json):
    allowed = []
    for f in files_json:
        path = f.get("filename", "")
        status = f.get("status", "")
        if status not in {"added", "modified"}:
            continue
        if not path.endswith(".json"):
            continue
        if not path.startswith(ROOT_PREFIX):
            continue
        parts = path.split("/")  # ["cves", "2025", ...]
        if len(parts) >= 3 and parts[1] in YEARS:
            allowed.append(path)
    return allowed

def _list_all_json_paths_recursively():
    url = f"https://api.github.com/repos/{OWNER}/{REPO}/git/trees/{BRANCH}?recursive=1"
    r = requests.get(url, headers=_gh_headers(), timeout=180)
    r.raise_for_status()
    tree = r.json().get("tree", [])
    out = []
    for node in tree:
        if node.get("type") != "blob":
            continue
        path = node.get("path", "")
        if path.endswith(".json") and path.startswith(ROOT_PREFIX):
            parts = path.split("/")
            if len(parts) >= 3 and parts[1] in YEARS:
                out.append(path)
    return out

def _raw_url(path: str) -> str:
    return f"https://raw.githubusercontent.com/{OWNER}/{REPO}/{BRANCH}/{path}"

def pull_cves_incremental_and_write_partitioned_by_year():
    s3 = S3Hook(aws_conn_id="AWS_DEFAULT")

    # 1) HEAD and checkpoint
    head_sha = _get_head_sha()
    last_sha = _read_text_from_s3(s3, STATE_BUCKET, STATE_KEY)
    print(f"HEAD={head_sha}; LAST={last_sha}")

    # 2) decide paths
    if last_sha:
        cmp = _compare_commits(last_sha, head_sha)
        paths = _filter_cve_paths(cmp.get("files", []))
        if cmp.get("too_large"):
            print("Compare too_large=true; falling back to sparse clone.")
            paths = _list_paths_via_sparse_clone()
    else:
        paths = _list_all_json_paths_recursively()
        if not paths:
            print("Trees API returned 0; falling back to sparse clone for first run.")
            paths = _list_paths_via_sparse_clone()

    # 3) fetch & build rows (THIS RUN ONLY)
    session = requests.Session()
    rows = []
    for i, path in enumerate(paths, 1):
        url = _raw_url(path)
        resp = session.get(url, headers=_gh_headers(), timeout=120)
        if resp.status_code != 200:
            if i % 500 == 0:
                print(f"WARN: {url} -> {resp.status_code}; skipping")
            continue

        text = resp.text
        data_hash = hashlib.md5(text.encode()).hexdigest()

        # derive year from path: cves/<year>/...
        parts = path.split("/")
        year = parts[1] if len(parts) > 1 else "unknown"

        # extract CVE ID
        cve_id = None
        try:
            parsed = json.loads(text)
            cve_id = (parsed.get("cveMetadata") or {}).get("cveId")
        except Exception:
            print(f"WARN: invalid JSON at {url}; storing as-is")
        if not cve_id:
            cve_id = pathlib.Path(path).stem

        rows.append({
            "data_id": i,  # per-run sequence
            "timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
            "year": year,
            "cve_id": cve_id,
            "source": url,
            "data_hash": data_hash,
            "raw_data": text
        })

        if i % 1000 == 0:
            print(f"[{i}/{len(paths)}] processed")

    if not rows:
        print("No new rows to write for this run.")
        if head_sha and head_sha != last_sha:
            _write_text_to_s3(s3, STATE_BUCKET, STATE_KEY, head_sha)
        return

    df_run = pd.DataFrame(rows, columns=["data_id","timestamp","year","cve_id","source","data_hash","raw_data"])

    # 4) write partitioned Parquet: year=YYYY/ingestion_date=YYYY-MM-DD/...
    ingestion_date = datetime.utcnow().strftime("%Y-%m-%d")
    run_ts = datetime.utcnow().strftime("%Y%m%dT%H%M%S")

    # write one file per YEAR present in this run (so partitions are clean)
    for yr, df_part in df_run.groupby("year"):
        s3_key = f"{DATA_PREFIX}/year={yr}/ingestion_date={ingestion_date}/cve_batch_{run_ts}.parquet"
        buf = BytesIO()
        table = pa.Table.from_pandas(df_part, preserve_index=False)
        pq.write_table(table, buf, compression="snappy")
        buf.seek(0)

        s3_client = s3.get_conn()
        s3_client.put_object(
            Bucket=BUCKET,
            Key=s3_key,
            Body=buf.getvalue(),
            ContentType="application/x-parquet"
        )
        print(f"Wrote {len(df_part)} rows to s3://{BUCKET}/{s3_key}")

    # 5) update checkpoint after successful writes
    _write_text_to_s3(s3, STATE_BUCKET, STATE_KEY, head_sha)
    print(f"Checkpoint updated to {head_sha}")

with DAG(
    dag_id="cvelist_incremental_to_s3_parquet_partitioned_by_year",
    description="Incremental CVE ingest to S3 Parquet partitioned by year + day (SHA incremental)",
    start_date=datetime(2025, 10, 3),
    schedule="@daily",
    catchup=False,
    tags=["security","cve","s3","github","incremental","partitioned","year"],
    dagrun_timeout=timedelta(hours=8),
    max_active_runs=1,
) as dag:
    pull_and_store = PythonOperator(
        task_id="pull_cve_incremental_store_parquet_partitioned_by_year",
        python_callable=pull_cves_incremental_and_write_partitioned_by_year,
        execution_timeout=timedelta(hours=7),
    )
