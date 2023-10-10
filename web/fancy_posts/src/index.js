const express = require('express');
const helmet = require('helmet');
const path = require('path');
const httpMiddleware = require('./src/middlewares/http.middlware');
const apiV1Router = require('./src/routes/api.v1.route');
const { setupDefaults } = require('./src/utils/setup.utils');

require('dotenv').config();

const app = express();

app.disable('x-powered-by');
app.use(httpMiddleware.noCachingMiddleware);

// APIs
app.use('/api/v1', apiV1Router);
app.get('/health', (req, res) => res.status(200).send('This is fine'));

// Frontend
app.use(express.static('public'));
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname + '/public/index.html'));
});

// custom errors handlers
app.use(httpMiddleware.notFoundMiddleware);
app.use(httpMiddleware.customErrorMiddleware);

const PORT = process.env.PORT || 3000;
const server = app.listen(PORT, '0.0.0.0', () => {
    console.log(`Example app listening on port ${PORT}`);
});
setupDefaults();

process.on('SIGTERM', () => {
    server.close();
});
