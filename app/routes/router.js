// route.js
const express = require('express');
const router = express.Router();

const net = require('net');
const server = require('http').createServer(router);
const io = require('socket.io')(server);
const controller = require('../controller/pyController');
const db = require('../model/databaseModel'); // db nesnesini içe aktar

// Python script çalıştırma
router.get('/run-script', function(req, res) {
    const scriptPath = 'C:\\Users\\muham\\apps\\CySec\\app\\pyscripts\\master\\hello.py'; 

    controller.runPythonScript(scriptPath, function(err, output) {
        if (err) {
            return res.status(500).send(err.message);
        }
        // res.send(output);
        // index.ejs dosyasını render ediyoruz ve scriptOutput adında bir değişken ile python scriptinin çıktısını gönderiyoruz
        res.render('index', { scriptOutput: output }); 
        console.log('Çıktı: ' + output);
    });
});

router.get('/run-logcollector', function(req, res) {
    const scriptPath = 'C:\\Users\\muham\\apps\\CySec\\app\\pyscripts\\master\\LogCollector.py'; 
    console.log('Running LogCollector.py');
    controller.runPythonScript(scriptPath, function(err, output) {
        if (err) {
            return res.status(500).send(err.message);
        }
        console.log('Çıktı: ' + output);
        console.log('Hatan: ' + err.message);
    });
});

router.get('/run-ipcontroller', function(req, res) {
    const scriptPath = 'C:\\Users\\muham\\apps\\CySec\\app\\pyscripts\\master\\IPController.py'; 

    controller.runPythonScript(scriptPath, function(err, output) {
        if (err) {
            return res.status(500).send(err.message);
        }
        console.log('Çıktı: ' + output);
        console.log('Hatan: ' + err.message);
    });
});

router.get('/some-route', function(req, res) {
    db.all('SELECT * FROM IpLogs LIMIT 10', [], (err, rows) => {
        if (err) {
            throw err;
        }
        res.send(rows);
    });
});

// Ana sayfa yolu
router.get('/', (req, res) => {
    res.render('index'); // index.ejs şablonunu render etme
});

router.get('/settings', function(req, res) {
    res.render('settings');
});

module.exports = router;