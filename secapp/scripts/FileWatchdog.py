
"""
Dosya Sistemi İzleme: Dosya oluşturma, silme, değiştirme, erişim gibi değişiklikleri
izleyen bir script. Bu, veri bütünlüğünü korumaya ve izinsiz erişimi tespit etmeye yardımcı olur.
"""

import os
import time
import sqlite3
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

DB_PATH = 'db.sqlite3'


def create_db():
    db = sqlite3.connect(DB_PATH)
    cursor = db.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS file_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type TEXT,
            file_path TEXT,
            timestamp TEXT
        )
    ''')
    db.commit()
    db.close()


def get_watch_path():
    db = sqlite3.connect(DB_PATH)
    cursor = db.cursor()
    cursor.execute('SELECT path FROM watch_paths LIMIT 1')
    result = cursor.fetchone()
    db.close()
    if result:
        return result[0]
    else:
        raise Exception("Watch path not found in database.")


class Watcher:
    def __init__(self, directory_to_watch):
        self.DIRECTORY_TO_WATCH = directory_to_watch
        self.observer = Observer()

    def run(self):
        event_handler = Handler()
        self.observer.schedule(event_handler, self.DIRECTORY_TO_WATCH, recursive=True)
        self.observer.start()
        try:
            while True:
                time.sleep(5)
        except KeyboardInterrupt:
            self.observer.stop()
        self.observer.join()

class Handler(FileSystemEventHandler):
    @staticmethod
    def process(event):
        """
            event.event_type: 'modified', 'created', 'moved', or 'deleted'
            event.src_path: path to the file or directory
        """
        print(f"Event Type: {event.event_type}, Path: {event.src_path}")
        db = sqlite3.connect(DB_PATH)
        cursor = db.cursor()
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(time.time()))
        cursor.execute('''
            INSERT INTO file_logs (event_type, file_path, timestamp)
            VALUES (?, ?, ?)
        ''', (event.event_type, event.src_path, timestamp))
        db.commit()
        db.close()
        # Burada belirli olaylar için uyarı mekanizması ekleyebilirsiniz
        if event.event_type == 'deleted':
            print(f"ALERT: File Deleted - {event.src_path}")
        elif event.event_type == 'created':
            print(f"ALERT: File Created - {event.src_path}")

    def on_modified(self, event):
        self.process(event)

    def on_created(self, event):
        self.process(event)

    def on_deleted(self, event):
        self.process(event)

    def on_moved(self, event):
        self.process(event)

if __name__ == '__main__':
    try:
        watch_path = get_watch_path()
        w = Watcher(watch_path)
        w.run()
    except Exception as e:
        print(f"Error: {e}")
