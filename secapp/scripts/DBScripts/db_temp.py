
"""
Verileri eventdescription tablosuna ekleme fonksiyonu
Sütun başlarında EventID ve Description başlıkları olmak zorunda
"""
import pandas as pd
import sqlite3

db = sqlite3.connect('db.sqlite3')
cursor = db.cursor()

cursor.execute('DELETE FROM error_logs')

db.commit()
db.close()