import os
import sys
from google.cloud import bigquery


def truncate_bigquery_table():
    """
    Truncates the BigQuery table specified by the BQ_TABLE_ID environment variable.
    """
    # Default matches the configuration found in poc-loader.py and verify-bq.py
    table_id = os.getenv("BQ_TABLE_ID", "pd-demo-202510.vulnerability_archive.raw_scan_logs")

    try:
        print(f"Attempting to truncate BigQuery table: {table_id}...")
        client = bigquery.Client()

        # BigQuery supports the TRUNCATE TABLE DDL statement.
        # This is more efficient than DELETE for clearing an entire table.
        query = f"TRUNCATE TABLE `{table_id}`"
        query_job = client.query(query)

        # Wait for the job to complete; this will raise an exception if the job fails
        query_job.result()

        print("--------------------------------------------------")
        print("Truncate Status: SUCCESS")
        print(f"Table '{table_id}' has been cleared.")
        print("--------------------------------------------------")

    except Exception as e:
        print(f"Error truncating BigQuery table: {e}")
        sys.exit(1)


if __name__ == "__main__":
    truncate_bigquery_table()
