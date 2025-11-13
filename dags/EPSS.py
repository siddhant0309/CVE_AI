from airflow import DAG
import json
from airflow.operators.python import PythonOperator
from airflow.providers.amazon.aws.hooks.s3 import S3Hook
from datetime import datetime
import requests
import pandas as pd
from io import StringIO, BytesIO
import hashlib
import gzip

def pull_epss_data_and_upload_to_s3():
    # Generate today's date for EPSS URL
    today = datetime.now().strftime('%Y-%m-%d')
    epss_url = f"https://epss.empiricalsecurity.com/epss_scores-{today}.csv.gz"
    
    print(f"Fetching EPSS data for {today}")
    
    # Pull gzipped CSV data from EPSS
    response = requests.get(epss_url)
    response.raise_for_status()
    
    # Decompress gzip content
    with gzip.open(BytesIO(response.content), 'rt') as f:
        # Read CSV - EPSS has a comment line starting with #, skip it
        epss_df = pd.read_csv(f, comment='#', skipinitialspace=True)
    
    # Print column names to debug
    print(f"Column names in EPSS CSV: {epss_df.columns.tolist()}")
    print(f"First few rows:\n{epss_df.head()}")
    
    # The first column should be the CVE ID - get the actual column name
    cve_column = epss_df.columns[0]
    
    # Filter for CVE-2024-* and CVE-2025-* only
    epss_df = epss_df[epss_df[cve_column].str.startswith(('CVE-2024-', 'CVE-2025-'), na=False)]
    
    print(f"Filtered to {len(epss_df)} CVEs from 2024 and 2025")
    
    # Convert filtered data to JSON string
    json_data = epss_df.to_json(orient='records')
    
    # Hash the JSON data
    data_hash = hashlib.md5(json_data.encode()).hexdigest()
    
    s3_hook = S3Hook(aws_conn_id='AWS_DEFAULT')
    bucket_name = 'medallion-data-cve'
    s3_key = 'Raw_Container/epss_data_master.parquet'
    
    # Try to read existing Parquet file from S3
    try:
        existing_parquet = s3_hook.get_key(key=s3_key, bucket_name=bucket_name)
        df = pd.read_parquet(BytesIO(existing_parquet.get()['Body'].read()))
        next_id = int(df['Data_ID'].max()) + 1
        print(f"Existing file found. Next ID: {next_id}")
    except Exception as e:
        print(f"No existing file found. Creating new file. Error: {e}")
        df = pd.DataFrame(columns=['Data_ID', 'Timestamp', 'Source_URL', 'Data_Hash', 'Raw_Data'])
        next_id = 1
    
    # Check if hash already exists (data unchanged)
    if 'Data_Hash' in df.columns and data_hash in df['Data_Hash'].values:
        print("Data unchanged, skipping upload")
        return
    
    # Create new row with fetched data
    new_row = pd.DataFrame({
        'Data_ID': [next_id],
        'Timestamp': [datetime.now().strftime('%Y-%m-%d %H:%M:%S')],
        'Source_URL': [epss_url],
        'Data_Hash': [data_hash],
        'Raw_Data': [json_data]  # Entire JSON stored as string
    })
    
    # Append new row to existing data
    df = pd.concat([df, new_row], ignore_index=True)
    
    # Convert to Parquet and upload back to S3
    parquet_buffer = BytesIO()
    df.to_parquet(parquet_buffer, index=False, engine='pyarrow')
    parquet_buffer.seek(0)
    
    s3_hook.load_bytes(
        bytes_data=parquet_buffer.read(),
        key=s3_key,
        bucket_name=bucket_name,
        replace=True
    )
    
    print(f"Successfully added row {next_id} to s3://{bucket_name}/{s3_key}")
    print(f"Data Hash: {data_hash}")

with DAG(
    'epss_to_s3_Raw',
    description='Pull EPSS data daily and append to master Parquet in S3',
    start_date=datetime(2025, 10, 9),
    schedule='@daily',
    catchup=False,
    tags=['security', 'epss', 's3']
) as dag:
    
    pull_and_store = PythonOperator(
        task_id='pull_epss_store_s3',
        python_callable=pull_epss_data_and_upload_to_s3
    )
