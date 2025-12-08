import os
from dotenv import load_dotenv
import snowflake.connector

load_dotenv()   # loads .env from current folder

def get_connection():
    return snowflake.connector.connect(
        user=os.getenv("SNOWFLAKE_USER"),
        password=os.getenv("SNOWFLAKE_PAT"),   # keeping exactly what you used
        account=os.getenv("SNOWFLAKE_ACCOUNT"),
        warehouse=os.getenv("SNOWFLAKE_WAREHOUSE"),
        database=os.getenv("SNOWFLAKE_DATABASE"),
        schema=os.getenv("SNOWFLAKE_SCHEMA"),
        role=os.getenv("SNOWFLAKE_ROLE"),
    )

# This part still runs when you execute snowflake_test.py directly
if __name__ == "__main__":
    conn = get_connection()
    print("CONNECTED")

    cur = conn.cursor()
    cur.execute("SELECT CURRENT_VERSION()")
    print(cur.fetchone())

    cur.close()
    conn.close()



