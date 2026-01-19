import os
import sys
from google.cloud import bigquery


def verify_bigquery_connection():
    """
    Verifies connectivity to BigQuery and counts records in the specified table.
    Expects environment variable: BQ_TABLE_ID.
    """
    # Default matches the configuration found in poc-loader.py
    table_id = os.getenv("BQ_TABLE_ID", "pd-demo-202510.vulnerability_archive.raw_scan_logs")

    try:
        print(f"Attempting to connect to BigQuery and query table: {table_id}...")
        client = bigquery.Client()

        # Using backticks for the table ID to handle project.dataset.table format correctly
        query = f"SELECT COUNT(*) as total FROM `{table_id}`"
        query_job = client.query(query)

        # This will raise an exception if the connection fails or table doesn't exist
        results = query_job.result()

        for row in results:
            count = row.total
            print("--------------------------------------------------")
            print("Connection Status: SUCCESS")
            print(f"Table '{table_id}' count: {count}")
            print("--------------------------------------------------")

    except Exception as e:
        print(f"Error connecting to BigQuery: {e}")
        sys.exit(1)


if __name__ == "__main__":
    verify_bigquery_connection()
