
"""
HATALI DOSYA SORUNU BULAMADIM
"""
import psutil
import time

def get_process_network_usage():
    process_data = []
    for process in psutil.process_iter(['pid', 'name', 'connections']):
        for conn in process.connections():
            if conn.status == psutil.CONN_ESTABLISHED and isinstance(conn, psutil.pconn):
                # Sadece aktif bağlantılar ve pconn nesneleri
                laddr = f"{conn.laddr.ip}:{conn.laddr.port}"
                raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "UNKNOWN"
                try:
                    with process.oneshot():
                        process_name = process.name()
                        pid = process.pid
                except psutil.NoSuchProcess:
                    continue

                process_data.append({
                    "pid": pid,
                    "process_name": process_name,
                    "local_address": laddr,
                    "remote_address": raddr,
                    "bytes_sent": conn.stats.bytes_sent,
                    "bytes_recv": conn.stats.bytes_recv
                })
    return process_data


def format_bytes(size):
    """Baytları KB, MB, GB veya TB'ye dönüştürür"""
    power = 2**10
    n = 0
    power_labels = {0: '', 1: 'K', 2: 'M', 3: 'G', 4: 'T'}
    while size > power:
        size /= power
        n += 1
    return f"{size:.2f} {power_labels[n]}B"

if __name__ == "__main__":
    while True:
        process_data = get_process_network_usage()
        print("-" * 50)
        for data in process_data:
            print(f"PID: {data['pid']}, İşlem: {data['process_name']}, ")
            print(f" Yerel: {data['local_address']}, Uzak: {data['remote_address']},")
            print(f" Gönderilen: {format_bytes(data['bytes_sent'])}, Alınan: {format_bytes(data['bytes_recv'])}")
        time.sleep(5)