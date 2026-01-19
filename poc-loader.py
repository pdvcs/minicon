import os
import json
import random
import logging
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from google.cloud import bigquery
import psycopg2
from faker import Faker

# configuration (Set via Env Vars or Edit Here)
ALLOY_HOST = os.getenv("ALLOY_HOST", "10.x.x.x")
ALLOY_PORT = int(os.getenv("ALLOY_PORT", "5432"))
ALLOY_DB = os.getenv("ALLOY_DB", "postgres")
ALLOY_USER = os.getenv("ALLOY_USER", "postgres")
ALLOY_PASS = os.getenv("ALLOY_PASS", "")
BQ_TABLE_ID = os.getenv("BQ_TABLE_ID", "pd-demo-202510.vulnerability_archive.raw_scan_logs")
TOTAL_RECORDS = 5000  # Number of records to simulate

# Setup Logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
fake = Faker()


# mock data generator (simulating Cloud SQL stream)
def generate_scan_stream(num_records):
    """Generates a stream of raw scan findings."""
    assets = [f"asset-{i}" for i in range(1, 101)]  # 100 Unique Assets
    cves = [f"CVE-2024-{random.randint(1000, 9999)}" for i in range(50)]  # 50 Unique CVEs

    for _ in range(num_records):
        asset = random.choice(assets)
        cve = random.choice(cves)
        yield {
            "scan_id": fake.uuid4(),
            "scan_date": datetime.now().isoformat(),
            "asset_id": asset,  # The "Technical ID"
            "cve_id": cve,
            "cvss_score": round(random.uniform(4.0, 10.0), 1),
            "severity": random.choice(["Medium", "High", "Critical"]),
            "summary": f"Found vulnerability {cve} in {asset}. Recommendation: Patch immediately.",
        }


# enrichment logic
def enrich_record(record):
    """Simulates looking up Asset Identity & Business Context."""
    # Logic: map technical 'asset-X' to stable 'service-Y'
    asset_num = int(record["asset_id"].split("-")[1])
    stable_id = f"payment-service-{asset_num % 10}"  # Only 10 real services

    record["stable_identity"] = stable_id
    record["team_owner"] = "Checkout Team" if asset_num % 2 == 0 else "Platform Team"
    record["region"] = "us-east1" if asset_num < 50 else "europe-west2"
    return record


# bigquery writer (archive)
def write_to_bq(bq_client, batch):
    """Writes raw history to BigQuery."""
    rows_to_insert = []
    for item in batch:
        rows_to_insert.append(
            {
                "asset_id": item["asset_id"],
                "scan_date": item["scan_date"],
                "cve_id": item["cve_id"],
                "findings_json": json.dumps(item),  # Store full blob
                "ingestion_time": datetime.now().isoformat(),
            }
        )

    logging.info(f"Archiving {len(batch)} records to BigQuery ...")
    errors = bq_client.insert_rows_json(BQ_TABLE_ID, rows_to_insert)
    if errors:
        logging.error(f"BigQuery Errors: {errors}")
    else:
        logging.info(f"Archived {len(batch)} records to BigQuery.")


# alloydb writer (state upsert)
def write_to_alloy(conn, batch):
    """Upserts current state to AlloyDB."""
    cursor = conn.cursor()

    # SQL for "Insert or Update if exists"
    upsert_sql = """
    INSERT INTO active_vulnerabilities 
    (stable_identity, technical_id, team_owner, region, cve_id, cvss_score, severity, status, first_seen, last_seen, finding_summary)
    VALUES (%s, %s, %s, %s, %s, %s, %s, 'Open', NOW(), NOW(), %s)
    ON CONFLICT (stable_identity, cve_id) 
    DO UPDATE SET
        last_seen = NOW(),
        technical_id = EXCLUDED.technical_id,
        status = CASE 
            WHEN active_vulnerabilities.status = 'Fixed' THEN 'Open'
            ELSE active_vulnerabilities.status 
        END;
    """

    data_tuples = [
        (
            r["stable_identity"],
            r["asset_id"],
            r["team_owner"],
            r["region"],
            r["cve_id"],
            r["cvss_score"],
            r["severity"],
            r["summary"],
        )
        for r in batch
    ]

    try:
        cursor.executemany(upsert_sql, data_tuples)
        conn.commit()
        logging.info(f"Upserted {len(batch)} records to AlloyDB.")
    except Exception as e:
        conn.rollback()
        logging.error(f"AlloyDB Error: {e}")
    finally:
        cursor.close()


# main
def run_poc():
    logging.info("Starting Mini-PoC Stream")

    # Connect to Clients
    bq_client = bigquery.Client()
    alloy_conn = psycopg2.connect(
        host=ALLOY_HOST,
        port=ALLOY_PORT,
        database=ALLOY_DB,
        user=ALLOY_USER,
        password=ALLOY_PASS,
    )

    batch_size = 100
    batch_buffer = []

    # ThreadPool to handle BQ and AlloyDB writes in parallel
    with ThreadPoolExecutor(max_workers=4) as executor:
        for raw_record in generate_scan_stream(TOTAL_RECORDS):
            # Step 1: Enrich
            enriched = enrich_record(raw_record)
            batch_buffer.append(enriched)

            # Step 2: Flush Batch
            if len(batch_buffer) >= batch_size:
                # Copy list for thread safety
                current_batch = list(batch_buffer)
                batch_buffer.clear()

                # Async Write to BQ (Fire and Forget)
                executor.submit(write_to_bq, bq_client, current_batch)

                # Sync Write to AlloyDB (Keep State Consistent)
                write_to_alloy(alloy_conn, current_batch)

    logging.info("Waiting for BigQuery tasks to complete ...")
    executor.shutdown(wait=True)  # Wait for all tasks to complete
    logging.info("PoC Completed Successfully")
    alloy_conn.close()


if __name__ == "__main__":
    run_poc()
