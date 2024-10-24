const express = require('express');
const bodyParser = require('body-parser');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const db = require('./config/db'); // File koneksi database
const app = express();

// Middleware
app.use(bodyParser.urlencoded({ extended: false }));
app.use(express.static('public')); // Untuk CSS dan asset lainnya
app.use(session({
    secret: 'yourSecretKey',
    resave: false,
    saveUninitialized: true,
}));
app.set('view engine', 'ejs');

// Landing page route (akan menjadi home page setelah login)
app.get('/', (req, res) => {
    if (req.session.user) {
        res.render('profile', { user: req.session.user });
    } else {
        res.redirect('/auth/login');
    }
});

// Rute untuk menampilkan halaman login
app.get('/auth/login', (req, res) => {
    res.render('login');
});

// Rute untuk menampilkan halaman register
app.get('/auth/register', (req, res) => {
    res.render('register');
});

// Rute untuk menangani proses login
app.post('/auth/login', (req, res) => {
    const { username, password } = req.body;
    const query = 'SELECT * FROM users WHERE username = ?';

    db.query(query, [username], async (err, results) => {
        if (err) throw err;

        if (results.length > 0) {
            const user = results[0];
            const match = await bcrypt.compare(password, user.password);
            
            if (match) {
                req.session.user = user; // Menyimpan info user di session
                res.redirect('/');
            } else {
                res.send('Password salah!');
            }
        } else {
            res.send('Username tidak ditemukan!');
        }
    });
});

// Rute untuk menangani proses register
app.post('/auth/register', async (req, res) => {
    const { username, email, password } = req.body;
    const queryCheckUser = 'SELECT * FROM users WHERE username = ?';

    db.query(queryCheckUser, [username], async (err, results) => {
        if (err) throw err;

        if (results.length > 0) {
            res.send('Username sudah terdaftar!');
        } else {
            const hashedPassword = await bcrypt.hash(password, 10);
            const queryInsert = 'INSERT INTO users (username, email, password) VALUES (?, ?, ?)';
            db.query(queryInsert, [username, email, hashedPassword], (err, result) => {
                if (err) throw err;
                res.redirect('/auth/login');
            });
        }
    });
});

// Rute untuk menampilkan halaman profile setelah login
app.get('/profile', (req, res) => {
    if (req.session.user) {
        res.render('profile', { user: req.session.user });
    } else {
        res.redirect('/auth/login');
    }
});

// Rute untuk logout
app.get('/auth/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/auth/login');
});

// Tambahkan di sini: Route untuk About dan Contact
// Route untuk halaman About
app.get('/about', (req, res) => {
    res.render('about'); // Render file about.ejs yang ada di folder views
});

// Route untuk halaman Contact
app.get('/contact', (req, res) => {
    res.render('contact'); // Render file contact.ejs yang ada di folder views
});

// Menjalankan server di port 3000
app.listen(3000, () => {
    console.log("Server berjalan di port 3000, buka web melalui http://localhost:3000");
});
