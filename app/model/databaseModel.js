const sqlite3 = require('sqlite3').verbose();

// Veritabanı dosyasının yolu
const path = require('path');
const dbPath = path.resolve(__dirname, '../pyscripts/master/Database.db');

// Veritabanı bağlantısını oluşturun
const db = new sqlite3.Database(dbPath, (err) => {
    if (err) {
        console.error('Veritabanına bağlanırken bir hata oluştu:', err.message);
    } else {
        console.log('Veritabanına başarıyla bağlandı.');
    }
});

// Veritabanı ekleme işlemi
const addData = (data) => {
    const sql = 'INSERT INTO TableName (column1, column2) VALUES (?, ?)';
    db.run(sql, [data.column1, data.column2], function(err) {
        if (err) {
            console.error('Veritabanına veri eklenirken bir hata oluştu:', err.message);
        } else {
            console.log('Veri başarıyla eklendi. Eklenen verinin ID\'si:', this.lastID);
        }
    });
};

// Veritabanı silme işlemi
const deleteData = (id) => {
    const sql = 'DELETE FROM TableName WHERE id = ?';
    db.run(sql, id, function(err) {
        if (err) {
            console.error('Veritabanından veri silinirken bir hata oluştu:', err.message);
        } else {
            console.log('Veri başarıyla silindi. Silinen verinin ID\'si:', id);
        }
    });
};

// Veritabanı güncelleme işlemi
const updateData = (id, newData) => {
    const sql = 'UPDATE TableName SET column1 = ?, column2 = ? WHERE id = ?';
    db.run(sql, [newData.column1, newData.column2, id], function(err) {
        if (err) {
            console.error('Veritabanında veri güncellenirken bir hata oluştu:', err.message);
        } else {
            console.log('Veri başarıyla güncellendi. Güncellenen verinin ID\'si:', id);
        }
    });
};

// Veritabanından veri alma işlemi
const getData = () => {
    const sql = 'SELECT * FROM TableName';
    db.all(sql, [], (err, rows) => {
        if (err) {
            console.error('Veritabanından veri alınırken bir hata oluştu:', err.message);
        } else {
            console.log('Veriler:');
            rows.forEach((row) => {
                console.log(row);
            });
        }
    });
};

// Bağlantıyı kapatmak için 
// db.close();

module.exports = db; // db nesnesini dışa aktar