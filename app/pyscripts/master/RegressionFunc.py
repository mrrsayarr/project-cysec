"""
Verileri Sınıflandırma Fonksiyonları
"""

import joblib
import pandas as pd
from sklearn.tree import DecisionTreeClassifier, DecisionTreeRegressor


def train_model_and_save():
    # Veri setini yükle
    data = pd.read_csv("../sets/data1234.csv", sep=";")

    # Veriyi işle
    data['EventID'] = pd.to_numeric(data['EventID'])

    # Bağımsız ve bağımlı değişkenleri ayır
    X = data[["EventID"]]
    y = data["Level"]

    # Karar ağacı sınıflandırıcı modelini oluştur ve eğit
    model = DecisionTreeClassifier(min_samples_leaf=6)
    model.fit(X, y)

    # Eğitilmiş modeli bir dosyaya kaydet
    joblib.dump(model, "trained_model.joblib")
    print("Model başarıyla kaydedildi.")


def load_and_predict(event_id):
    # Özellik isimleri olmayan bir DataFrame oluştur
    X = pd.DataFrame({"EventID": [event_id]})

    # Eğitilmiş modeli yükle
    model = joblib.load("trained_model.joblib")

    # EventID'ye göre verinin seviyesini tahmin et
    predicted_level = model.predict(X)

    return predicted_level[0]

    # Test verileri üzerinde doğruluğu değerlendir
    # y_pred = model.predict(X)
    # accuracy = accuracy_score(y, y_pred)

    # print("Model Doğruluğu:", accuracy)


# Eğitim adımını yorumdan çıkarın ve bir kez çalıştırın
# train_model_and_save()
# MODEL EGITIMI ICIN BURAYI ACMAN LAZIM, KAYDEDINCE KAPATABILIRSIN

from sklearn.model_selection import KFold
from sklearn.metrics import mean_squared_error
import numpy as np


def predict_from_matlab_model_free(training_data, prediction_data):
    """
    MATLAB'da eğitilmiş bir regresyon ağacı modelini kullanarak tahmin yapar.

    Args:
        training_data (pandas.DataFrame): Modelin eğitildiği veri seti.
        prediction_data (pandas.DataFrame): Tahmin yapılacak veriler.

    Returns:
        numpy.ndarray: Tahmin edilen değerler.
    """

    # ---------------------------------------------------
    # Veri İşleme ve Hazırlık
    # ---------------------------------------------------

    # MATLAB modelindeki sütun adlarıyla uyumluluk için sütun adlarını düzeltme
    training_data.columns = ['column_1', 'column_2']
    prediction_data.columns = ['column_2']

    # Tahmin için kullanılacak sütunu seçme
    X_train = training_data[['column_2']]
    y_train = training_data['column_1']
    X_pred = prediction_data[['column_2']]

    # ---------------------------------------------------
    # Model Eğitimi (Decision Tree Regressor)
    # ---------------------------------------------------

    # MATLAB modelindeki parametrelere uygun olarak model oluşturma
    model = DecisionTreeRegressor(min_samples_leaf=1)

    # Modeli eğitim verileriyle eğitme
    model.fit(X_train, y_train)

    # ---------------------------------------------------
    # Çapraz Doğrulama (KFold)
    # ---------------------------------------------------

    # MATLAB modelindeki gibi 50 katlı çapraz doğrulama
    kf = KFold(n_splits=50, shuffle=True, random_state=42)

    rmse_scores = []
    for train_index, test_index in kf.split(X_train):
        X_train_fold, X_test_fold = X_train.iloc[train_index], X_train.iloc[test_index]
        y_train_fold, y_test_fold = y_train.iloc[train_index], y_train.iloc[test_index]

        model.fit(X_train_fold, y_train_fold)
        y_pred_fold = model.predict(X_test_fold)
        rmse_scores.append(mean_squared_error(y_test_fold, y_pred_fold, squared=False))

    # Ortalama RMSE skorunu hesaplama
    avg_rmse = np.mean(rmse_scores)
    print(f"Ortalama RMSE (50 katlı çapraz doğrulama): {avg_rmse:.4f}")

    # ---------------------------------------------------
    # Tahmin
    # ---------------------------------------------------

    # Tahmin verileri üzerinde tahmin yapma
    predictions = model.predict(X_pred)

    # ---------------------------------------------------
    # Sonuçları Döndürme
    # ---------------------------------------------------

    return predictions
