const Database = require('better-sqlite3');
const fs = require('fs');

const db = new Database(':memory:');

const migration = fs.readFileSync('db/setup.sql', 'utf8');
db.exec(migration);

module.exports = db;
