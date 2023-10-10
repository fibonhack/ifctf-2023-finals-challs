function enforceJsonContentTypeMiddleware(req, res, next) {
    if (req.method !== 'POST' && req.method !== 'PATCH') return next();
    if (req.headers?.['content-type'] !== 'application/json') return res.status(400).send('Invalid Content-Type');
    next();
}

function handleInvalidJSONMiddleware(err, req, res, next) {
    if (err.type === 'entity.too.large') return res.status(400).send('Request size is too large');
    if (err.type === 'entity.parse.failed') return res.status(400).send('Invalid JSON');
    return res.status(400).send('Invalid request body');
}

function notFoundMiddleware(req, res, next) {
    res.status(404).send('And you call yourself a Rocket Scientist!');
}

function customErrorMiddleware(err, req, res, next) {
    console.error(err.stack);
    res.status(500).send("I think ... err ... I think ... I think I'll go home");
}

function noCachingMiddleware(req, res, next) {
    res.set('Cache-control', 'no-store');
    next();
}

module.exports = {
    enforceJsonContentTypeMiddleware,
    handleInvalidJSONMiddleware,
    notFoundMiddleware,
    customErrorMiddleware,
    noCachingMiddleware,
};
