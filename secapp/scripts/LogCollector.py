
"""
Level açıklamaları ile yapan fonksiyonları eklendi
Artık PredictValue değerini yazıyor

Log Analiz: Mevcut log dosyalarını analiz eden ve desenleri, anormallikleri ve potansiyel
sorunları arayan bir script. Bu, sistemin genel durumunu anlamaMıza ve sorunları daha hızlı
bir şekilde çözmeYE yardımcı olur.
"""

import os
import sqlite3
import traceback
import win32evtlog
import json
import time
from RegressionFunc import load_and_predict

def classify_event_id(event_id):
    return load_and_predict(event_id)

"""

"""
def log_error_to_db(error_message):
    db = sqlite3.connect('db.sqlite3')
    cursor = db.cursor()
    cursor.execute('''
        INSERT INTO error_logs (ErrorMessage)
        VALUES (?)
    ''', (error_message,))
    db.commit()
    db.close()

def get_security_event_logs():
    logs = []
    handle = win32evtlog.OpenEventLog(None, "Security")
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    total_records = win32evtlog.GetNumberOfEventLogRecords(handle)
    events = win32evtlog.ReadEventLog(handle, flags, 0)
    for event in events:
        level_titles = {
            0: "Bilgi",
            1: "Denetim Basarisi",
            2: "Uyari",
            3: "Denetim Basarisizligi",
            4: "Hata",
            5: "Kritik",
            6: "Ozel",
            7: "Basarili Denetim",
            8: "Basarisiz Denetim"
        }
        predicted_value = classify_event_id(event.EventID)
        log_data = {
            "EventID": int(event.EventID),  # int64 -> int dönüşümü
            "PredictedValue": int(predicted_value),  # int64 -> int dönüşümü
            "SourceName": event.SourceName,
            "Status": level_titles.get(event.EventType, "Bilinmeyen"),  # Level seviyesine karşılık gelen başlık
            "Channel": "Security",
            "Message": event.StringInserts,
            "TimeGenerated": str(event.TimeGenerated)  # Oluşturulma zamanını ekledik
        }
        logs.append(log_data)
    win32evtlog.CloseEventLog(handle)
    return logs

def save_logs_to_json(logs, filename):
    with open(filename, "a") as f:
        for log in logs:
            json.dump(log, f)
            f.write("\n")
    print(f"Event logs appended to {filename}")

def save_logs_to_db(logs):
    db = sqlite3.connect('db.sqlite3')
    cursor = db.cursor()
    for log in logs:
        cursor.execute('''
            INSERT INTO events (EventID, PredictedValue, SourceName, Level, Channel, Message, TimeGenerated)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
        log["EventID"], log["PredictedValue"], log["SourceName"], log["Status"], log["Channel"], str(log["Message"]), log["TimeGenerated"]))
    db.commit()
    db.close()

def check_and_reset_file_size(file_path, max_size_mb=5):
    file_size_mb = os.path.getsize(file_path) / (1024 * 1024)
    if file_size_mb > max_size_mb:
        open(file_path, 'w').close()
        print(f"{file_path} dosyası {max_size_mb} MB boyutunu aştığı için sıfırlandı.")
    else:
        pass
    print(f"{file_path} dosyasının boyutu {file_size_mb} MB ve {max_size_mb} MB sınırından küçük.")

def main():
    while True:
        try:
            security_logs = get_security_event_logs()
            save_logs_to_json(security_logs, "Logs/LogCollectorOutput.json")
            save_logs_to_db(security_logs)
            check_and_reset_file_size("Logs/LogCollectorOutput.json", max_size_mb=5)
            time.sleep(60)
        except Exception as e:
            error_message = traceback.format_exc()
            log_error_to_db(error_message)

if __name__ == "__main__":
    main()
