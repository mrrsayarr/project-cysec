
"""
Verileri eventdescription tablosuna ekleme fonksiyonu
Sütun başlarında EventID ve Description başlıkları olmak zorunda
"""
import pandas as pd
import sqlite3

# Verileri manuel olarak oluştur
data = {
    "EventID": [16384, 12, 13, 18, 800, 4103, 4106, 4104, 4105, 24577],
    "PredictedValue": [4, 4, 4, 4, 4, 4, 5, 5, 5, 4],
    "Message": [None, None, None, None, None, None, None, None, None, None],
    "SourceName": [None, None, None, None, None, None, None, None, None, None],
    "Status": [None, None, None, None, None, None, None, None, None, None],
    "Channel": [None, None, None, None, None, None, None, None, None, None]
}

# Verileri bir pandas DataFrame'e dönüştür
df = pd.DataFrame(data)

# Veritabanına bağlanma
db_path = 'Database.db'  # Veritabanının yolu
db = sqlite3.connect(db_path)
cursor = db.cursor()

# DataFrame'deki her satırı tabloya ekle
for index, row in df.iterrows():
    cursor.execute('''
        INSERT OR IGNORE INTO events (EventID, PredictedValue, Message, SourceName, Status, Channel)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (row['EventID'], row['PredictedValue'], row['Message'], row['SourceName'], row['Status'], row['Channel']))

# Değişiklikleri kaydetme
db.commit()
db.close()