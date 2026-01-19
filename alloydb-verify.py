import os
import psycopg2
import sys

def verify_alloydb_connection():
    """
    Verifies connectivity to AlloyDB and counts records in the active_vulnerabilities table.
    Expects environment variables: ALLOY_HOST, ALLOY_PASS, ALLOY_USER (optional), ALLOY_DB (optional).
    """
    host = os.getenv("ALLOY_HOST")
    port = os.getenv("ALLOY_PORT", "5432")
    database = os.getenv("ALLOY_DB", "postgres")
    user = os.getenv("ALLOY_USER", "postgres")
    password = os.getenv("ALLOY_PASS")

    if not host or not password:
        print("Error: Please set ALLOY_HOST and ALLOY_PASS environment variables.")
        sys.exit(1)

    try:
        print(f"Attempting to connect to {host}...")
        conn = psycopg2.connect(
            host=host,
            port=port,
            database=database,
            user=user,
            password=password,
            connect_timeout=5
        )
        
        with conn.cursor() as cursor:
            cursor.execute("SELECT COUNT(*) FROM active_vulnerabilities;")
            count = cursor.fetchone()[0]
            print("--------------------------------------------------")
            print(f"Connection Status: SUCCESS")
            print(f"Table 'active_vulnerabilities' count: {count}")
            print("--------------------------------------------------")
            
        conn.close()
    except Exception as e:
        print(f"Error connecting to AlloyDB: {e}")
        sys.exit(1)

if __name__ == "__main__":
    verify_alloydb_connection()
