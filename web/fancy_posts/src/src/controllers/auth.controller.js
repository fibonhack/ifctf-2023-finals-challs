const db = require('../models/db');
const bcrypt = require('bcrypt');
const { generateAccessToken } = require('../utils/jwt.utils');
const { checkExact, checkSchema, validationResult } = require('express-validator');
const { v4: uuidv4 } = require('uuid');

const login = [
    checkExact(
        checkSchema(
            {
                username: {
                    errorMessage: 'Invalid username parameter',
                    isString: true,
                    notEmpty: true,
                    matches: {
                        options: /^[\w]+$/,
                    },
                },
                password: {
                    errorMessage: 'Invalid password parameter',
                    isString: true,
                    notEmpty: true,
                },
            },
            ['body'],
        ),
    ),

    function (req, res) {
        const validationErrors = validationResult(req);
        if (!validationErrors.isEmpty()) return res.status(400).send({ success: false, error: validationErrors.array()[0].msg });

        const user = db.prepare('SELECT password FROM user WHERE username = ?').get(req.body.username);
        if (user?.password === undefined)
            return res.status(401).send({
                success: false,
                error: 'Invalid username/password',
            });

        return bcrypt
            .compare(req.body.password, user.password)
            .then(match => {
                if (!match) return res.status(401).send({ success: false, error: 'Invalid username/password' });

                return res.send({
                    success: true,
                    data: { accessToken: generateAccessToken(req.body.username) },
                });
            })
            .catch(() => res.status(401).send({ success: false, error: 'Invalid username/password' }));
    },
];

const register = [
    checkExact(
        checkSchema(
            {
                username: {
                    errorMessage: 'Invalid username parameter',
                    isString: true,
                    isLength: {
                        options: { min: 3, max: 32 },
                    },
                    matches: {
                        options: /^[\w]+$/,
                    },
                },
                password: {
                    errorMessage: 'Invalid password parameter',
                    isString: true,
                    isLength: {
                        options: { min: 8, max: 128 },
                    },
                },
            },
            ['body'],
        ),
    ),

    function (req, res) {
        const validationErrors = validationResult(req);
        if (!validationErrors.isEmpty()) return res.status(400).send({ success: false, error: validationErrors.array()[0].msg });

        const user = db.prepare('SELECT password FROM user WHERE username = ?').get(req.body.username);
        if (user !== undefined) return res.status(400).send({ success: false, error: 'Username already exists' });

        return bcrypt
            .hash(req.body.password, 10)
            .then(passwordHash => {
                db.prepare('INSERT INTO user (id, username, password) VALUES (:id, :username, :password)').run({
                    id: uuidv4(),
                    username: req.body.username,
                    password: passwordHash,
                });
                return res.sendStatus(204);
            })
            .catch(() => res.status(401).send({ success: false, error: 'Invalid username/password' }));
    },
];

module.exports = {
    register,
    login,
};
