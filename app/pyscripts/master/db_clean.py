

"""
Manuel Eski Logları Silme: python db_clean.py
"""

import sqlite3
import time

def delete_old_logs(db_path, days_old=30):
    current_time = time.time()
    cutoff_time = current_time - (days_old * 86400)  # 86400 saniye = 1 gün

    # Veritabanına bağlanma
    db = sqlite3.connect(db_path)
    cursor = db.cursor()

    # Eski IP loglarını silme
    cursor.execute('''
        DELETE FROM IpLogs WHERE (strftime('%s','now') - strftime('%s', datetime(ID, 'unixepoch'))) > ?
    ''', (cutoff_time,))

    # Eski güvenlik olaylarını silme
    cursor.execute('''
        DELETE FROM events WHERE (strftime('%s','now') - strftime('%s', datetime(ID, 'unixepoch'))) > ?
    ''', (cutoff_time,))

    # Değişiklikleri kaydetme
    db.commit()
    db.close()

# Eski logları silme fonksiyonunu çalıştır (örnek kullanım)
if __name__ == "__main__":
    delete_old_logs('Database.db', days_old=30)
