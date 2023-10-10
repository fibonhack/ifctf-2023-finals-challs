const jwt = require('jsonwebtoken');

function generateAccessToken(username) {
    return jwt.sign({ username: username }, process.env.JWT_SECRET, { algorithm: 'HS256', expiresIn: '30m' });
}

module.exports = {
    generateAccessToken,
};
