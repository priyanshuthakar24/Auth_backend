const router = require('express').Router();
const { login, signup, logout, verifyEmail, forgotPassword, resetPassword, checkAuth, validationtoken } = require('../controller/auth.controller')
const { verifyToken } = require('../middleware/verifyToken');


router.get('/', async (req, res, next) => {
  res.send({ message: 'Ok api is working 🚀' });
});

router.get('/check-auth', verifyToken, checkAuth);

router.post('/signup', signup);
router.post('/login', login);
router.post('/logout', logout);

router.post('/verify-email', verifyEmail);
router.post('/forgot-password', forgotPassword);
router.post('/reset-password/:token', resetPassword);
module.exports = router;
