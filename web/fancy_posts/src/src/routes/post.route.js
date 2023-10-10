const express = require('express');
const router = express.Router();
const postController = require('../controllers/post.controller');
const authMiddleware = require('../middlewares/auth.middleware');

router.use(authMiddleware.getUserId);

router.get('/', postController.post_list);
router.post('/', postController.post_create);
router.delete('/:id', postController.post_delete);

module.exports = router;
