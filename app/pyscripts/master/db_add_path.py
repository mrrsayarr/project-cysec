import sqlite3

def update_database():
    db = sqlite3.connect('Database.db')
    cursor = db.cursor()

    # watch_paths tablosu
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS watch_paths (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            path TEXT NOT NULL
        )
    ''')

    # Yeni yol ekleme
    path_to_add = r"C:\Users\muham\OneDrive\Masaüstü\Chatbox\proje\proje\securitydatasets\2022.08.03\json"
    cursor.execute('''
        INSERT INTO watch_paths (path) VALUES (?)
    ''', (path_to_add,))

    db.commit()
    db.close()

# Update için 1 defa çalıştırılır
if __name__ == "__main__":
    update_database()
    print("Veritabanı güncellendi ve yeni yol eklendi.")
