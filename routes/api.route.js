const router = require('express').Router();
const { login, signup, logout, verifyEmail, forgotPassword, resetPassword, checkAuth, validationtoken } = require('../controller/auth.controller')
const { verifyToken } = require('../middleware/verifyToken');
const { body } = require('express-validator');

router.get('/', async (req, res, next) => {
  res.send({ message: 'Ok api is working 🚀' });
});

router.get('/check-auth', verifyToken, checkAuth);

//? Signup
router.post('/signup', [
  body('email').isEmail().withMessage('Is not a Valid Email'),
  body('password').isLength({ min: 6 }).withMessage('Password is must be at least 6 characters'),
  body('name').isLength({ min: 3 }).withMessage('Minimum 3 character are required and no Numeric character ')
], signup);

//? Login
router.post('/login', [
  body('email').isEmail().withMessage('Is not a valid Email'),
  body('password').isLength({ min: 6 }).withMessage('Password is must be at least 6 characters')
], login);

//? Logout
router.post('/logout', logout);

//? Verify-Email
router.post('/verify-email', verifyEmail);

//? Forget-Password
router.post('/forgot-password', [body('email').isEmail().withMessage('Is not a valid email')], forgotPassword);

//? Reset-Password
router.post('/reset-password/:token', [body('password').isLength({ min: 6 }).withMessage('Password is must be at least 6 characters')], resetPassword);


module.exports = router;
