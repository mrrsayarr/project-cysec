// route.js
const express = require('express');
const router = express.Router();

const net = require('net');
const server = require('http').createServer(router);
const io = require('socket.io')(server);
const controller = require('../controller/pyController');

// Python script çalıştırma
router.get('/run-script', function(req, res) {
    const scriptPath = 'C:\\Users\\muham\\apps\\CySec\\app\\pyscripts\\master\\hello.py'; // Dosya yolu türkçe karakter olmadan vermen gerekir

    controller.runPythonScript(scriptPath, function(err, output) {
        if (err) {
            return res.status(500).send(err.message);
        }
        res.send(output);
        console.log('Çıktı: ' + output);
        // console.log('hata: ' + err);
    });
});

// Ana sayfa yolu
router.get('/', (req, res) => {
    res.render('index'); // index.ejs şablonunu render etme
});

module.exports = router;