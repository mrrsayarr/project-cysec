import os
import sqlite3
import pandas as pd
import traceback
from RegressionFunc import load_and_predict

def classify_event_id(event_id):
    return load_and_predict(event_id)

def log_error_to_db(error_message):
    db = sqlite3.connect('db.sqlite3')
    cursor = db.cursor()
    cursor.execute('''
        INSERT INTO error_logs (ErrorMessage)
        VALUES (?)
    ''', (error_message,))
    db.commit()
    db.close()

def save_logs_to_db(df):
    db = sqlite3.connect('db.sqlite3')
    cursor = db.cursor()
    for _, row in df.iterrows():
        cursor.execute('''
            INSERT INTO events (EventID, Level)
            VALUES (?, ?)
        ''', (row["EventID"], row["PredictedValue"]))
    db.commit()
    db.close()

def read_and_analyze_csv():
    # Verileri manuel olarak oluştur
    data = {
        "EventID": [16384, 12, 13, 18, 800, 4103, 4106, 4104, 4105, 24577],
        "PredictedValue": [4, 4, 4, 4, 4, 4, 5, 5, 5, 4],
        "Message": ["None", "None", "None", "None", "None", "None", "None", "None", "None", "None"],
        "SourceName": ["None", "None", "None", "None", "None", "None", "None", "None", "None", "None"],
        "Status": ["None", "None", "None", "None", "None", "None", "None", "None", "None", "None"],
        "Channel": ["None", "None", "None", "None", "None", "None", "None", "None", "None", "None"]
    }

    # Verileri bir pandas DataFrame'e dönüştür
    df = pd.DataFrame(data)

    # Eksik değerleri 'Unknown' ile doldur
    df.fillna('Unknown', inplace=True)

    # DataFrame'deki 'None' değerlerin sayısını kontrol et
    print(df.isnull().sum())

    # EventID sütununu sınıflandır ve döndürülen değeri kontrol et
    df['PredictedValue'] = df['EventID'].apply(lambda x: type(classify_event_id(x)))

    print(df['PredictedValue'].unique())  # Bu satır, döndürülen tüm benzersiz değer türlerini yazdırır

    # Verileri analiz et (örnek olarak, her bir PredictedValue için sayıları hesapla)
    analysis_result = df['PredictedValue'].value_counts()

    # Verileri 'events' tablosuna kaydet
    save_logs_to_db(df)
    print("Veriler veritabanına kaydedildi.")

    return analysis_result
def main():
    try:
        analysis_result = read_and_analyze_csv()
        if analysis_result is not None:
            print(analysis_result)
    except Exception as e:
        error_message = traceback.format_exc()
        log_error_to_db(error_message)

if __name__ == "__main__":
    main()