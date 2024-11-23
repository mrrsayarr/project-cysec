"""
Değişiklikler:

Log Dosyası: Değişiklikler registry_changes.log adlı bir dosyaya kaydedilir.
Değişiklik Bilgileri: Değişen anahtarın adı (key_name), değeri (key_data) ve türü (key_type) log dosyasına yazdırılır.
Zaman Damgası: Değişikliğin yapıldığı zaman da log dosyasına eklenir.

Geliştirme Önerileri:
Log dosyasına değişikliği yapan işlemin adını ekleyin.
Farklı değişiklik türlerini (oluşturma, silme, değiştirme) ayırt edin ve log dosyasına kaydedin.
Kritik değişiklikler için uyarı bildirimleri (e-posta, SMS vb.) gönderin.
Log dosyasını döndürerek veya belirli bir boyuta ulaştığında arşivleyerek yönetin.
"""

import win32con
import win32api
import win32security

# İzlenecek kayıt defteri anahtarları
registry_keys_to_monitor = [
    r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run"
]

def monitor_registry_changes():
    # Güvenlik tanımlayıcısı oluştur
    everyone_sid = win32security.LookupAccountName(None, "Everyone")[0]
    access_mask = win32con.GENERIC_READ | win32con.GENERIC_WRITE | win32con.GENERIC_EXECUTE

    # Her kayıt defteri anahtarı için izleyici oluştur
    for registry_key in registry_keys_to_monitor:
        # Anahtarı aç
        hkey = win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE, registry_key, 0, win32con.KEY_READ)
        # İzleyici oluştur
        reg_notify_change_key_value(hkey, True, win32api.REG_NOTIFY_CHANGE_LAST_SET, None, False)

def reg_notify_change_key_value(hkey, watch_subtree, notify_filter, hwnd, asynchronous):
    win32api.RegNotifyChangeKeyValue(hkey, watch_subtree, notify_filter, hwnd, asynchronous)
    # Değişen değerin bilgilerini al
    key_name, key_type, key_data = win32api.RegQueryValueEx(hkey, "")
    # Log dosyasına yaz
    with open("registry_changes.log", "a") as f:
        f.write(f"[{time.ctime()}] Anahtar: {key_name}, Tür: {key_type}, Veri: {key_data}\n")

if __name__ == "__main__":
    monitor_registry_changes()
    # Programı sürekli çalışır durumda tutmak için (örneğin, döngü veya başka bir mekanizma)