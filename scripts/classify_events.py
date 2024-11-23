"""
Verileri Sınıflandırma İşlemleri
"""

from RegressionFunc import load_and_predict
from sklearn.metrics import accuracy_score


def classify_event_ids(event_ids):
    predicted_levels = []
    for event_id in event_ids:
        predicted_level = load_and_predict(event_id)
        predicted_levels.append(predicted_level)
        print(f"EventID: {event_id}, Tahmin Edilen Seviye: {predicted_level}")

    return predicted_levels


def calculate_accuracy(true_levels, predicted_levels):
    accuracy = accuracy_score(true_levels, predicted_levels)
    print(f"Doğruluk: {accuracy}")


# Örnek EventID'leri tanımla
# event_ids = [16384, 4673, 4689, 12]

"""
AŞAĞISI SADECE ÖRNEK İÇİN, SİLERSİN
"""

# Örnek EventID'leri tanımla
event_ids = [16384, 4673, 4689, 12, 5, 7, 4105, 4103, 4106, 4104]  # DOĞRU SINIFLANDIRMA YAPILDI
true_levels = [4, 0, 0, 4, 4, 4, 5, 4, 5, 4]  # Gerçek seviyeleri de tanımla

# Her EventID için sınıflandırma yap
predicted_levels = classify_event_ids(event_ids)

# Doğruluk değerini hesapla ve yazdır
calculate_accuracy(true_levels, predicted_levels) # Hata verirse Listelerin tutarsız olmasından kaynaklanır
