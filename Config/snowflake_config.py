import os
from dotenv import load_dotenv
from snowflake.snowpark import Session

load_dotenv()

def get_snowflake_session():
    """
    Create and return a Snowflake Snowpark session.
    """
    connection_params = {
        "account": os.getenv("SNOWFLAKE_ACCOUNT"),
        "user": os.getenv("SNOWFLAKE_USER"),
        "password": os.getenv("SNOWFLAKE_PAT"),
        "warehouse": os.getenv("SNOWFLAKE_WAREHOUSE"),
        "database": os.getenv("SNOWFLAKE_DATABASE"),
        "schema": os.getenv("SNOWFLAKE_SCHEMA"),
        "role": os.getenv("SNOWFLAKE_ROLE"),
    }
    
    missing = [k for k, v in connection_params.items() if not v]
    if missing:
        raise ValueError(f"Missing environment variables: {', '.join(missing)}")
    
    return Session.builder.configs(connection_params).create()

