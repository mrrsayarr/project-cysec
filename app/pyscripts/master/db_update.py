
"""
Database güncellemesini yapan fonksiyon
"""

import sqlite3

def update_database():
    db = sqlite3.connect('Database.db')
    cursor = db.cursor()

    # cursor.execute("UPDATE events SET SourceName = 'Microsoft-Windows-Security-Auditing' WHERE SourceName IS 'Bilinmiyor' ")
    # cursor.execute("ALTER TABLE events ADD COLUMN TimeGenerated TEXT;")
    # cursor.execute("DELETE FROM eventdescription;")
    cursor.execute("DELETE FROM eventdescription;")
    """
    cursor.execute('''  
            DELETE FROM news
            WHERE ID = 100
        ''')
    """

    """
    cursor.execute('''
            DELETE FROM events
            WHERE ID >= 62
        ''')
    """



    """
    cursor.execute('''
            CREATE TABLE IF NOT EXISTS file_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT,
                file_path TEXT,
                timestamp TEXT
            )
        ''')

    # watch_paths tablosu
    cursor.execute('''
            CREATE TABLE IF NOT EXISTS watch_paths (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                path TEXT NOT NULL
            )
        ''')
    """


    """
    # Hata logları için tablo oluşturma
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS error_logs (
            ID INTEGER PRIMARY KEY AUTOINCREMENT,
            ErrorMessage TEXT,
            ErrorTime TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    """

    """
    cursor.execute('''
            CREATE TABLE IF NOT EXISTS news (
                ID INTEGER PRIMARY KEY AUTOINCREMENT,
                SourceName TEXT,
                Title TEXT,
                PublishedAt TEXT,
                URL TEXT
            )
        ''')

    """

    # cursor.execute("DELETE FROM IpLogs")    # Tablodaki tüm verileri siler
    # cursor.execute("DELETE FROM file_logs")

    db.commit()
    db.close()

# Update için 1 defa çalıştırılır
if __name__ == "__main__":
    update_database()

"""
        # Önceki sütunlarla uyumlu tablo oluştur
    cursor.execute('''
            CREATE TABLE IF NOT EXISTS IpLogs (
                ID INTEGER PRIMARY KEY AUTOINCREMENT,
                PID INT,
                Process TEXT,
                Local TEXT,
                Remote TEXT,
                Protocol TEXT
            )
        ''')

    cursor.execute('''
            ALTER TABLE IpLogs
            ADD COLUMN LocalIP TEXT
        ''')

    cursor.execute('''
            ALTER TABLE IpLogs
            ADD COLUMN LocalPort INT
        ''')

    cursor.execute('''
            ALTER TABLE IpLogs
            ADD COLUMN RemoteIP TEXT
        ''')

    cursor.execute('''
            ALTER TABLE IpLogs
            ADD COLUMN RemotePort INT
        ''')
"""