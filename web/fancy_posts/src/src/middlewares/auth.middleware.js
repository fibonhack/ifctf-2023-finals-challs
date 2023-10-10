const jwt = require('jsonwebtoken');
const db = require('../models/db');

// NOTE: Sets res.locals.username
function jwtAuthMiddleware(req, res, next) {
    const authHeader = req.headers['authorization'];
    if (authHeader === undefined) return res.sendStatus(401);

    const token = authHeader && authHeader.split(' ')?.[1];
    if (typeof token !== 'string' || token === '') return res.sendStatus(401);

    jwt.verify(token, process.env.JWT_SECRET, (err, obj) => {
        if (err) return res.sendStatus(401);
        res.locals.username = obj.username;
        next();
    });
}

function getUserId(req, res, next) {
    const user = db.prepare('SELECT id FROM user u WHERE u.username = ?').get(res.locals.username);
    res.locals.userid = user.id;
    next();
}

module.exports = {
    jwtAuthMiddleware,
    getUserId,
};
