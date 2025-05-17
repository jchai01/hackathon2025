import sqlite3
import logging
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)
DB_NAME = 'geolocation_cache.db'

def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS geo_cache (
            ip_address TEXT PRIMARY KEY,
            latitude REAL,
            longitude REAL,
            city TEXT,
            country TEXT,
            status TEXT, -- 'success', 'failed_api', 'failed_timeout', 'private', 'pending'
            last_api_call INTEGER, -- UNIX timestamp of the last API call for this IP
            last_successful_lookup INTEGER, -- UNIX timestamp for successful lookup
            retries INTEGER DEFAULT 0
        )
    ''')
    # Index for faster lookups of pending IPs
    cursor.execute('''
        CREATE INDEX IF NOT EXISTS idx_status_retries ON geo_cache (status, retries)
    ''')
    conn.commit()
    conn.close()
    logger.info(f"Database {DB_NAME} initialized/checked.")

def get_geolocated_ip_from_db(ip_address):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT latitude, longitude, city, country, status FROM geo_cache WHERE ip_address = ?", (ip_address,))
    row = cursor.fetchone()
    conn.close()
    if row:
        return {"ip": ip_address, "lat": row[0], "lon": row[1], "city": row[2], "country": row[3], "status": row[4]}
    return None

def add_ip_to_geolocate_queue(ip_address):
    """Adds an IP to the database with 'pending' status if not already processed or pending."""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT status FROM geo_cache WHERE ip_address = ?", (ip_address,))
    existing = cursor.fetchone()
    if not existing:
        logger.info(f"DB: Adding {ip_address} to geolocation queue (pending).")
        cursor.execute("INSERT INTO geo_cache (ip_address, status, last_api_call, retries) VALUES (?, 'pending', 0, 0)", (ip_address,))
        conn.commit()
    # Optionally, if it exists but failed long ago, you might re-queue it here.
    conn.close()


def update_geolocation_in_db(ip_address, geo_data_from_api):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    now_ts = int(datetime.now().timestamp())
    
    if geo_data_from_api.get("status") == "success":
        logger.info(f"DB: Successfully geolocated {ip_address}. Updating DB.")
        cursor.execute('''
            UPDATE geo_cache 
            SET latitude = ?, longitude = ?, city = ?, country = ?, status = 'success', last_api_call = ?, last_successful_lookup = ?, retries = retries + 1
            WHERE ip_address = ?
        ''', (geo_data_from_api.get("lat"), geo_data_from_api.get("lon"), 
              geo_data_from_api.get("city"), geo_data_from_api.get("country"), 
              now_ts, now_ts, ip_address))
    elif geo_data_from_api.get("status") == "private_or_reserved":
        logger.info(f"DB: IP {ip_address} is private/reserved. Updating DB.")
        cursor.execute('''
            UPDATE geo_cache
            SET status = 'private', last_api_call = ?, retries = retries + 1
            WHERE ip_address = ?
        ''', (now_ts, ip_address))
    else: # API call failed for some reason
        api_status = geo_data_from_api.get("status", "failed_unknown") # e.g., 'failed_api', 'failed_timeout'
        logger.warning(f"DB: Geolocation failed for {ip_address} (status: {api_status}). Updating DB.")
        cursor.execute('''
            UPDATE geo_cache 
            SET status = ?, last_api_call = ?, retries = retries + 1
            WHERE ip_address = ?
        ''', (api_status, now_ts, ip_address))
    conn.commit()
    conn.close()

def get_ips_to_process_from_db(limit=5, max_retries=5, retry_delay_hours=24):
    """
    Gets IPs that are 'pending' or 'failed' (if retry delay has passed and retries < max_retries).
    Prioritizes 'pending' IPs.
    """
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    # Timestamp for retry_delay_hours ago
    retry_threshold_ts = int((datetime.now() - timedelta(hours=retry_delay_hours)).timestamp())
    
    # Prioritize 'pending' IPs first
    cursor.execute('''
        SELECT ip_address FROM geo_cache 
        WHERE status = 'pending' 
        ORDER BY last_api_call ASC, retries ASC 
        LIMIT ?
    ''', (limit,))
    pending_ips = [row[0] for row in cursor.fetchall()]
    
    remaining_limit = limit - len(pending_ips)
    
    failed_ips_to_retry = []
    if remaining_limit > 0:
        # Then select 'failed' IPs eligible for retry
        cursor.execute(f'''
            SELECT ip_address FROM geo_cache 
            WHERE status LIKE 'failed_%' AND retries < ? AND last_api_call < ?
            ORDER BY retries ASC, last_api_call ASC
            LIMIT ?
        ''', (max_retries, retry_threshold_ts, remaining_limit))
        failed_ips_to_retry = [row[0] for row in cursor.fetchall()]
        
    conn.close()
    
    ips_to_process = pending_ips + failed_ips_to_retry
    if ips_to_process:
        logger.info(f"DB: Found {len(ips_to_process)} IPs to geolocate (Pending: {len(pending_ips)}, Retrying Failed: {len(failed_ips_to_retry)}).")
    return ips_to_process

init_db() # Initialize DB when this module is imported