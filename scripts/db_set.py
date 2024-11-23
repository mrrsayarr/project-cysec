
"""
 DİKKAT ET
  DİKKAT ET
   DİKKAT ET
    DİKKAT ET
     DİKKAT ET
      DİKKAT ET
       DİKKAT ET
        DİKKAT ET
         DİKKAT ET
          DİKKAT ET

Database oluşturma ve tabloları oluşturma, ve diğer işlemler
"""

import sqlite3

def setup_database():
    db = sqlite3.connect('db.sqlite3')
    cursor = db.cursor()

    # cursor.execute('''
    #     CREATE TABLE IF NOT EXISTS IpLogs (
    #         ID INTEGER PRIMARY KEY AUTOINCREMENT,
    #         PID INT,
    #         Process TEXT,
    #         Local TEXT,
    #         Remote TEXT,
    #         Protocol TEXT
    #     )
    # ''')

    # cursor.execute('''
    #     CREATE TABLE IF NOT EXISTS events (
    #         ID INTEGER PRIMARY KEY AUTOINCREMENT,
    #         EventID INT,
    #         SourceName TEXT,
    #         Level TEXT,
    #         Channel TEXT,
    #         Message TEXT
    #     )
    # ''')

    
    cursor.execute('''
        DELETE FROM IpLogs
    ''')


    db.commit()
    db.close()

# Veritabanını ayarla (ilk kez çalıştırıldığında kullan)
if __name__ == "__main__":
    setup_database()
