
"""
API çağrılarını yakalar ve izler
"""

from mitmproxy import http
import time
import json
import sqlite3

DB_PATH = 'db.sqlite3'


def log_api_call_to_db(flow):
    try:
        db = sqlite3.connect(DB_PATH)
        cursor = db.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS api_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                method TEXT,
                url TEXT,
                request_headers TEXT,
                request_body TEXT,
                response_status_code INTEGER,
                response_headers TEXT,
                response_body TEXT,
                timestamp TEXT,
                response_time REAL
            )
        ''')
        db.commit()

        request_headers = json.dumps(dict(flow.request.headers))
        request_body = flow.request.get_text()
        response_headers = json.dumps(dict(flow.response.headers))
        response_body = flow.response.get_text()
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(flow.request.timestamp_start))
        response_time = flow.response.timestamp_end - flow.request.timestamp_start

        cursor.execute('''
            INSERT INTO api_logs (method, url, request_headers, request_body, response_status_code, response_headers, response_body, timestamp, response_time)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (flow.request.method, flow.request.url, request_headers, request_body, flow.response.status_code,
              response_headers, response_body, timestamp, response_time))

        db.commit()
        db.close()
        print(f"Logged API call to {flow.request.url}")  # Debugging
    except Exception as e:
        print(f"Database Error: {str(e)}")


def response(flow: http.HTTPFlow) -> None:
    try:
        print(f"Intercepted API call to {flow.request.url}")  # Debugging
        log_api_call_to_db(flow)
    except Exception as e:
        print(f"Error in response handling: {str(e)}")
