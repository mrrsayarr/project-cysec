
const express = require('express');
const path = require('path'); // path modülünü dahil edin
const router = express.Router();
const app = express();
const port = 3000;

const Route = require('./app/routes/router'); // Routes dahil etme

const bodyParser = require('body-parser');
app.use(bodyParser.urlencoded({ extended: false }));

app.use(express.static(path.join(__dirname, 'public'))); // Public klasörünü tanımlama işlemi (CSS ve Bootstrap dosyaları için)

app.use(express.json());
app.set("view engine", "ejs"); // Defining the image engine
app.set('views', path.join(__dirname, 'app/views')); // EJS şablon motoru

app.use('/', Route); // Uygulamanızın yollarını (routes) ayarlayın

app.listen(port, () => {console.log(`Uygulama http://localhost:${port} adresinde çalışıyor`);});