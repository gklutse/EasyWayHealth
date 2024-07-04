const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');
const pgp = require('pg-promise')();

dotenv.config();

const app = express();
app.use(cors({
    origin: '*',
    methods: ['GET', 'POST'],
    allowedHeaders: ['Content-Type', 'Authorization'],
}));
app.use(bodyParser.json());

const db = pgp({
    user: 'healthappuser',
    host: '192.168.255.139',
    database: 'healthapp',
    password: '$12YH43NO$',
    port: 5432,
});

app.post('/signup', async (req, res) => {
    const { email, password, name, role } = req.body;
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        await db.none('INSERT INTO users(email, password, name, role) VALUES($1, $2, $3, $4)', [email, hashedPassword, name, role]);
        res.status(201).send({ message: 'User created successfully' });
    } catch (error) {
        console.error('Error signing up:', error);
        res.status(500).send({ error: 'Error signing up' });
    }
});

app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const user = await db.oneOrNone('SELECT * FROM users WHERE email = $1', [email]);
        if (user && await bcrypt.compare(password, user.password)) {
            const token = jwt.sign({ email: user.email }, process.env.JWT_SECRET, { expiresIn: '1h' });
            res.send({ token });
        } else {
            res.status(400).send({ error: 'Invalid credentials' });
        }
    } catch (error) {
        console.error('Error logging in:', error);
        res.status(500).send({ error: 'Error logging in' });
    }
});

app.post('/forgot-password', async (req, res) => {
    const { email } = req.body;
    try {
        const user = await db.oneOrNone('SELECT * FROM users WHERE email = $1', [email]);
        if (user) {
            res.status(200).send({ message: 'Password reset link sent to your email.' });
        } else {
            res.status(400).send({ error: 'User not found.' });
        }
    } catch (error) {
        console.error('Error resetting password:', error);
        res.status(500).send({ error: 'Error resetting password' });
    }
});

app.post('/reset-password', async (req, res) => {
    const { email, newPassword } = req.body;
    try {
        const hashedPassword = await bcrypt.hash(newPassword, 10);
        await db.none('UPDATE users SET password = $1 WHERE email = $2', [hashedPassword, email]);
        res.status(200).send({ message: 'Password reset successfully' });
    } catch (error) {
        console.error('Error resetting password:', error);
        res.status(500).send({ error: 'Error resetting password' });
    }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
