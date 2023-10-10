const express = require('express');
const router = express.Router();
const profileController = require('../controllers/profile.controller');
const authMiddleware = require('../middlewares/auth.middleware');

router.use(authMiddleware.getUserId);

router.get('/me', profileController.profile_get);
router.get('/properties', profileController.property_list);
router.post('/properties', profileController.property_create);
router.delete('/properties/:id', profileController.property_delete);

module.exports = router;
