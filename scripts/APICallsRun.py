"""
APICallsFunc.py dosyasını başlatır

API İzleme: API çağrıları, yanıt süreleri, hata oranları ve
diğer metrikleri izleyen bir script. Bu, API performansını
analiz etmemize ve sorunları gidermemize yardımcı olabilir.
"""
import subprocess


def start_mitmproxy():
    try:
        # mitmdump komutunu çalıştır
        process = subprocess.Popen(['mitmdump', '-s', 'APICallsFunc.py'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        print("mitmdump başlatıldı")

        # Canlı çıktı gösterme
        while True:
            output = process.stdout.readline()
            if output == '' and process.poll() is not None:
                break
            if output:
                print(output.strip())

        process.wait()
    except KeyboardInterrupt:
        print("mitmdump durduruldu")
    except Exception as e:
        print(f"Hata: {str(e)}")


if __name__ == "__main__":
    start_mitmproxy()
