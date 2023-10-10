const express = require('express');
const httpMiddleware = require('../middlewares/http.middlware');
const authMiddleware = require('../middlewares/auth.middleware');
const authRouter = require('./auth.route');
const profileRouter = require('./profile.route');
const postRouter = require('./post.route');

const router = express.Router();

router.use(httpMiddleware.enforceJsonContentTypeMiddleware);
router.use(express.json({ limit: '1kb', strict: true, type: 'application/json' }));
router.use(httpMiddleware.handleInvalidJSONMiddleware);

router.use('/', authRouter);
router.use('/profile', authMiddleware.jwtAuthMiddleware, profileRouter);
router.use('/posts', authMiddleware.jwtAuthMiddleware, postRouter);

module.exports = router;
