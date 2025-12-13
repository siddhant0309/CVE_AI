from __future__ import annotations

from airflow import DAG
from airflow.operators.python import PythonOperator
from datetime import datetime, timedelta
import os
from io import BytesIO
import re

import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq


# ---------------------- CONFIG ----------------------
BUCKET = os.environ.get("S3_BUCKET", "medallion-data-cve")
AWS_CONN_ID = "AWS_DEFAULT"

# Silver inputs (S3)
CVE_SILVER_KEY = "Silver_Layer/cve_silver/cve_silver.parquet"
EPSS_SILVER_KEY = "Silver_Layer/epss_silver/epss_silver.parquet"
# KEV currently lives as a CSV in Silver_Layer
KEV_SILVER_KEY = "Silver_Layer/kev_flattened_latest_clean.csv"

# Gold output (S3)
GOLD_PREFIX = "Gold_Container/vuln_gold"
GOLD_FILE = f"{GOLD_PREFIX}/vuln_gold.parquet"


# ---------------------- S3 HELPERS ----------------------
def _read_parquet_to_df(s3, key: str) -> pd.DataFrame:
    body = s3.get_key(key, BUCKET).get()["Body"].read()
    tbl = pq.read_table(BytesIO(body))
    df = tbl.to_pandas()
    df.columns = [str(c).strip().lower() for c in df.columns]
    return df


def _read_csv_to_df(s3, key: str) -> pd.DataFrame:
    body = s3.get_key(key, BUCKET).get()["Body"].read()
    df = pd.read_csv(BytesIO(body))
    df.columns = [str(c).strip().lower() for c in df.columns]
    return df


def _write_df_to_parquet(s3, key: str, df: pd.DataFrame) -> None:
    buf = BytesIO()
    tbl = pa.Table.from_pandas(df, preserve_index=False)
    pq.write_table(tbl, buf, compression="snappy")
    buf.seek(0)
    s3.get_conn().put_object(
        Bucket=BUCKET,
        Key=key,
        Body=buf.getvalue(),
        ContentType="application/x-parquet",
    )


def _fill_unknown_strings(df: pd.DataFrame) -> pd.DataFrame:
    """
    For all object (string) columns:
      - Replace NULL / blanks / NA tokens with 'Unknown'
      - For *_norm columns, use 'unknown'
    """
    if df.empty:
        return df

    obj_cols = df.select_dtypes(include=["object"]).columns
    if not len(obj_cols):
        return df

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


# ---------------------- CWE URL HELPER ----------------------
def _build_cwe_reference_urls(cwe_value: str) -> str:
    """
    Input:  'CWE-79, CWE-89'  (or 'Unknown')
    Output: 'https://cwe.mitre.org/.../79.html, https://cwe.mitre.org/.../89.html'
            or 'Unknown' if no valid CWE pattern.
    """
    if not cwe_value or str(cwe_value).strip().lower() == "unknown":
        return "Unknown"

    text = str(cwe_value)
    matches = re.findall(r"CWE-(\d+)", text)
    if not matches:
        return "Unknown"

    urls = [
        f"https://cwe.mitre.org/data/definitions/{num}.html"
        for num in sorted(set(matches))
    ]
    return ", ".join(urls)


# ---------------------- CORE TRANSFORMATION ----------------------
def build_vuln_gold_from_silver() -> None:
    """
    Build semantic Gold snapshot:
      - Joins CVE + KEV + EPSS
      - KEV overrides DESCRIPTION / SOLUTION / CWE when present
      - Fills Unknown for strings, 0.0 for numeric scores
      - Builds combined_text for embeddings
      - Writes full Gold snapshot parquet to S3
    """
    from airflow.providers.amazon.aws.hooks.s3 import S3Hook

    s3 = S3Hook(aws_conn_id=AWS_CONN_ID)

    # --- Load Silver dataframes ---
    cve_df = _read_parquet_to_df(s3, CVE_SILVER_KEY)
    epss_df = _read_parquet_to_df(s3, EPSS_SILVER_KEY)
    kev_df = _read_csv_to_df(s3, KEV_SILVER_KEY)

    # Normalise KEV columns
    kev_df = kev_df.rename(
        columns={
            "cveid": "cve_id",
            "shortdescription": "kev_description",
            "requiredaction": "kev_required_action",
            "cwes": "kev_cwe",
        }
    )

    # --- Base CVE columns (added date_updated) ---
    base_cols = [
        "cve_id",
        "vendor_name_norm",
        "product_name_norm",
        "title",
        "description",
        "solution",
        "cvss_score",
        "cvss_severity",
        "reference_url",
        "cwes",
        "date_updated",      # <-- NEW: carry date_updated from CVE Silver
    ]
    cve_core = cve_df[base_cols].copy()

    # --- Join KEV ---
    kev_core = kev_df[
        ["cve_id", "kev_description", "kev_required_action", "kev_cwe"]
    ].copy()
    merged = cve_core.merge(kev_core, on="cve_id", how="left")

    # --- Join EPSS (robust to different column names) ---
    cols = [c.lower() for c in epss_df.columns]
    print("DEBUG EPSS COLUMNS:", cols)

    if {"cve_id", "epss_score", "epss_percentile"}.issubset(cols):
        epss_core = epss_df[["cve_id", "epss_score", "epss_percentile"]].copy()

    elif {"cve_id", "epss", "percentile"}.issubset(cols):
        epss_core = (
            epss_df.rename(
                columns={
                    "epss": "epss_score",
                    "percentile": "epss_percentile",
                }
            )[["cve_id", "epss_score", "epss_percentile"]]
            .copy()
        )

    else:
        # If it hits this, logs will show actual layout
        raise ValueError(f"Unexpected EPSS column layout in parquet: {cols}")

    merged = merged.merge(epss_core, on="cve_id", how="left")

    # --- KEV overrides ---
    # DESCRIPTION
    merged["description_final"] = merged["description"]
    merged.loc[
        merged["kev_description"].notna()
        & (merged["kev_description"].astype(str).str.strip() != ""),
        "description_final",
    ] = merged["kev_description"]

    # SOLUTION
    merged["solution_final"] = merged["solution"]
    merged.loc[
        merged["kev_required_action"].notna()
        & (merged["kev_required_action"].astype(str).str.strip() != ""),
        "solution_final",
    ] = merged["kev_required_action"]

    # CWE
    merged["cwe_final"] = merged["cwes"]
    merged.loc[
        merged["kev_cwe"].notna()
        & (merged["kev_cwe"].astype(str).str.strip() != ""),
        "cwe_final",
    ] = merged["kev_cwe"]

    # --- CWE reference URLs ---
    merged["cwe_reference_url"] = merged["cwe_final"].apply(
        _build_cwe_reference_urls
    )

    # --- Numeric nulls -> 0.0 ---
    for col in ["cvss_score", "epss_score", "epss_percentile"]:
        if col in merged.columns:
            merged[col] = pd.to_numeric(
                merged[col], errors="coerce"
            ).fillna(0.0)

    # --- Select final columns + rename (added date_updated) ---
    gold = merged[
        [
            "cve_id",
            "vendor_name_norm",
            "product_name_norm",
            "title",
            "description_final",
            "solution_final",
            "cvss_score",
            "cvss_severity",
            "reference_url",
            "cwe_final",
            "cwe_reference_url",
            "epss_score",
            "epss_percentile",
            "date_updated",        # <-- keep date_updated in Gold
        ]
    ].copy()

    gold = gold.rename(
        columns={
            "description_final": "description",
            "solution_final": "solution",
            "cwe_final": "cwe",
        }
    )

    # --- Fill Unknowns for string columns ---
    gold = _fill_unknown_strings(gold)

    # --- COMBINED_TEXT for embeddings

    def _build_combined_text(row: pd.Series) -> str:
        return (
            f"{row['cve_id']}. "
            f"Vendor: {row['vendor_name_norm']}. "
            f"Product: {row['product_name_norm']}. "
            f"Title: {row['title']}. "
            f"Description: {row['description']}. "
            f"Solution: {row['solution']}. "
            f"CVSS score: {row['cvss_score']} severity {row['cvss_severity']}. "
            f"Reference URL: {row['reference_url']}. "
            f"CWE(s): {row['cwe']}. "
            f"CWE reference URLs: {row['cwe_reference_url']}. "
            f"EPSS score: {row['epss_score']}. "
            f"EPSS percentile: {row['epss_percentile']}. "
            f"Last updated on: {row['date_updated']}."
        )

    gold["combined_text"] = gold.apply(_build_combined_text, axis=1)

    # --- Write Gold parquet to S3 ---
    _write_df_to_parquet(s3, GOLD_FILE, gold)


# ---------------------- DAG ----------------------
with DAG(
    dag_id="vuln_silver_to_gold_semantic",
    description=(
        "Build semantic Gold snapshot for CVE+KEV+EPSS "
        "(one row per CVE, combined_text for embeddings)"
    ),
    start_date=datetime(2025, 10, 15),
    schedule="@once",
    catchup=False,
    max_active_runs=1,
    dagrun_timeout=timedelta(hours=3),
    tags=["cve", "kev", "epss", "gold", "semantic", "vector"],
) as dag:
    PythonOperator(
        task_id="build_vuln_gold_from_silver",
        python_callable=build_vuln_gold_from_silver,
        execution_timeout=timedelta(hours=2),
    )
