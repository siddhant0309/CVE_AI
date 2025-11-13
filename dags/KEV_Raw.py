def pull_kev_data_and_upload_to_s3():
    github_url = "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json"
   
    # Pull JSON data from CISA GitHub
    response = requests.get(github_url)
    response.raise_for_status()
 
    data_hash = hashlib.md5(response.text.encode()).hexdigest()
   
    s3_hook = S3Hook(aws_conn_id='AWS_DEFAULT')
    bucket_name = 'medallion-data-cve'
    s3_key = 'Raw_Container/kev_data_master.csv'
   
    # Try to read existing file from S3
    try:
        existing_csv = s3_hook.read_key(key=s3_key, bucket_name=bucket_name)
        df = pd.read_csv(StringIO(existing_csv))
        next_id = int(df['data_id'].max()) + 1
        print(f"Existing file found. Next ID: {next_id}")
    except Exception as e:
        print(f"No existing file found. Creating new file. Error: {e}")
        df = pd.DataFrame(columns=['data_id', 'timestamp', 'source','data_hash', 'raw_data'])
        next_id = 1
   
    if 'data_hash' in df.columns and data_hash in df['data_hash'].values:
        print("Data unchanged, skipping upload")
        return
    # Create new row with fetched data
    else:
        new_row = pd.DataFrame({
            'data_id': [next_id],
            'timestamp': [datetime.now().strftime('%Y-%m-%d %H:%M:%S')],
            'source': [github_url],
            'data_hash': [data_hash],
            'raw_data': [response.text]
    })
   
    # Append new row to existing data
    df = pd.concat([df, new_row], ignore_index=True)
   
    # Convert to CSV and upload back to S3
    csv_data = df.to_csv(index=False)
    s3_hook.load_string(
        string_data=csv_data,
        key=s3_key,
        bucket_name=bucket_name,
        replace=True
    )
   
    print(f"Successfully added row {next_id} to s3://{bucket_name}/{s3_key}")
 
with DAG(
    'kev_to_s3_Raw',
    description='Pull CISA KEV data and append to master CSV in S3',
    start_date=datetime(2025, 10, 3),
    schedule='@daily',
    catchup=False,
    tags=['security', 'kev', 's3']
) as dag:
   
    pull_and_store = PythonOperator(
        task_id='pull_kev_store_s3',
        python_callable=pull_kev_data_and_upload_to_s3
    )