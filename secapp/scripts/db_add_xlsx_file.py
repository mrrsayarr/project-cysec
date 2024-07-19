
# Excel dosyasından verileri ekleme

import sqlite3

import pandas as pd


def update_database():
    db = sqlite3.connect('Database.db')
    cursor = db.cursor()

    # 'eventdescription' tablosundaki tüm verileri siler
    cursor.execute("DELETE FROM eventdescription;")

    # 'eventdescription' tablosuna veri ekler
    # Önce Excel dosyasını pandas DataFrame'ine yükleriz
    df = pd.read_excel('data2.xlsx')

    # DataFrame'deki her satırı 'eventdescription' tablosuna ekleriz
    for index, row in df.iterrows():
        cursor.execute("INSERT OR REPLACE INTO eventdescription(EventID, Description) VALUES(?, ?)", (row['EventID'], row['Description']))

    db.commit()
    db.close()

# Update için 1 defa çalıştırılır
if __name__ == "__main__":
    update_database()