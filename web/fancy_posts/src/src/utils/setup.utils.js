const db = require('../models/db');
const { v4: uuidv4 } = require('uuid');

function setupDefaults() {
    const username = 'admin';
    const key = 'flag';

    const value = process.env.FLAG;
    if (value === undefined) throw new Error('Missing default FLAG parameter in the environment');

    const user = db.prepare('SELECT id FROM user WHERE username = ?').get(username);
    if (user?.id === undefined) throw new Error(`Missing default user: ${username}`);

    let property = db.prepare('SELECT p.id FROM property p WHERE p.user_id = ? AND p.key = ?').get(user.id, key);
    if (property !== undefined) return;

    const newId = uuidv4();
    db.prepare('INSERT INTO property (id, user_id, key, value) VALUES (?, ?, ?, ?)').run(newId, user.id, key, value);
}

module.exports = {
    setupDefaults,
};
