const express = require("express");
const bcrypt = require('bcryptjs');
const jwt = require("jsonwebtoken");

const User = require("../models/User.model");
const router = express.Router();
const saltRounds = 10;

const { isAuthenticated } = require("../middlewares/jwt.middleware")

router.post('/signup', (req, res, next) => {

    const { username, password, campus, course } = req.body;

    if (username === '' || password === '') {
        res.status(400).json({ message: 'Provide username, password.' });
        return;
    }

    const passwordRegex = /(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{6,}/;
    if (!passwordRegex.test(password)) {
        res.status(400).json({ message: 'Password must have at least 6 characters and contain at least one number, one lowercase and one uppercase letter.' });
        return;
    }

    User.findOne({ username })
        .then(foundUser => {
            if (foundUser) {
                res.status(400).json({ message: "User already exists." });
                return;
            }

            const salt = bcrypt.genSaltSync(saltRounds);
            const hashedPassword = bcrypt.hashSync(password, salt);

            return User.create({ username, password: hashedPassword, campus, course });
        })
        .then(createdUser => {
            const { username, campus, course, _id } = createdUser;

            // Create a new object that doesn't expose the password
            const newUser = { username, campus, course, _id };

            res.status(201).json(newUser);
        })
        .catch(err => {
            console.log(err);
            res.status(500).json({ message: "Internal Server Error" })
        });
})


// POST  /auth/login
router.post('/login', (req, res, next) => {
    const { username, password } = req.body;

    // Check if username or password are provided as empty string 
    if (username === '' || password === '') {
        res.status(400).json({ message: "Provide both username and password." });
        return;
    }

    User.findOne({ username })
        .then((foundUser) => {

            if (!foundUser) {
                res.status(401).json({ message: "Username or password incorrect" })
                return;
            }

            const passwordCorrect = bcrypt.compareSync(password, foundUser.password);

            if (passwordCorrect) {
                const { _id, username, campus, course } = foundUser;

                const payload = { _id, username, campus, course };

                const authToken = jwt.sign(
                    payload,
                    process.env.TOKEN_SECRET,
                    { algorithm: 'HS256', expiresIn: "6h" }
                );

                res.status(200).json({ authToken: authToken });
            }
            else {
                res.status(401).json({ message: "Username or password incorrect" });
            }

        })
        .catch(err => res.status(500).json({ message: "Internal Server Error" }));
});


router.get('/verify', isAuthenticated, (req, res, next) => {
    return res.status(200).json(req.payload);
});

module.exports = router;