
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
    db = sqlite3.connect('../../db.sqlite3')
    cursor = db.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS firewallrule (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            description TEXT,
            action TEXT NOT NULL DEFAULT 'DROP',
            protocol TEXT NOT NULL DEFAULT 'TCP',
            source_ip TEXT,
            destination_ip TEXT,
            source_port TEXT,
            destination_port TEXT,
            enabled INTEGER NOT NULL DEFAULT 1
        )
    ''')

    db.commit()
    db.close()

# Veritabanını ayarla (ilk kez çalıştırıldığında kullan)
if __name__ == "__main__":
    setup_database()
