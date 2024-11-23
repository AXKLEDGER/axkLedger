const express = require('express');
const rateLimit = require('express-rate-limit');
const { check, validationResult } = require('express-validator');
const userController = require('../../controllers/users');
const { validateToken } = require('../../middleware/auth');

const router = express.Router();

// Rate limiter configurations
const createUserLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5,
  message: 'Too many account creation requests from this IP, please try again later.',
});

const profileLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: 'Too many requests to access profile from this IP, please try again later.',
});

// Common validation rules
const emailValidation = check('email').isEmail().withMessage('Please include a valid email');
const passwordValidation = () => check('password')
  .isLength({ min: 12 })
  .withMessage('Password must be at least 12 characters long.')
  // .matches(/[A-Z]/)
  // .withMessage('Password must contain at least one uppercase letter.')
  .matches(/[a-z]/)
  .withMessage('Password must contain at least one lowercase letter.')
  .matches(/[0-9]/)
  .withMessage('Password must contain at least one number.')
  .matches(/[\W_]/)
  .withMessage('Password must contain at least one special character.');

const transactionHashValidation = check('hash').isHexadecimal().notEmpty().withMessage('Transaction hash is required');

router.get('/profile', validateToken, userController.getUserProfile);

router.get('/tx/all', validateToken, userController.getUserTransactions);
router.get('/tx/complete', validateToken, userController.getUserCompleteTransactions);
router.get('/tx/pending', validateToken, userController.getUserPendingTransactions);

router.post('/', createUserLimiter, [
  emailValidation,
  passwordValidation(8),
], userController.createUser);

router.post('/profile', [
  validateToken,
  emailValidation,
  check('name').isString().notEmpty().withMessage('User name is required'),
], userController.updateProfile);

router.post('/password', [
  validateToken,
  emailValidation,
  passwordValidation(12),
], userController.updatePassword);

router.post('/change', [
  validateToken,
  emailValidation,
  passwordValidation(8),
  passwordValidation(12).custom((value, { req }) => {
    if (value === req.body.password) {
      throw new Error('New password must be different from the current password');
    }
    return true;
  }),
], userController.changePassword);

router.post('/forgot_password', [
  emailValidation,
], userController.sendResetEmailToken);

router.post('/forgot_password/:token', [
  emailValidation,
  passwordValidation(12),
  check('token').isJWT().notEmpty().withMessage('Reset token is required'),
], userController.verifyResetToken, userController.resetPassword);

router.post('/verify', [
  emailValidation,
  check('token').isJWT().notEmpty().withMessage('Token is required'),
], userController.sendVerification);

router.get('/otp/:otp', [
  check('otp').isNumeric().notEmpty().withMessage('OTP is required'),
], userController.verifyOTP);

router.get('/verify', [
  validateToken,
  check('x-auth-token').isJWT().notEmpty().withMessage('Token is required'),
], userController.createEmailToken);

router.get('/verify/:token', [
  check('token').isJWT().notEmpty().withMessage('Token is required'),
], userController.verifyToken);

router.get('/tx', [
  validateToken,
  transactionHashValidation,
], userController.getUserTransactionDetails);

module.exports = router;
