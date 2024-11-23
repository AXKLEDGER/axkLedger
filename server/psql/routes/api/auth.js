const express = require('express');
const router = express.Router();
const { check } = require('express-validator');
const { validateToken, validateFarmer } = require('../../middleware/auth');
const { createFarmerKey } = require('../../controllers/farmers');
const authController = require('../../controllers/auth');
const rateLimit = require('express-rate-limit');

// Common validation rules
const emailPasswordValidation = [
  check('email', 'Please include a valid email').isEmail(),
  check('password', 'Password is required').exists(),
];

const pinValidation = [
  check('pin', 'Pin is required').isNumeric().exists(),
];

const updatePinValidation = [
  check('currentPin', 'Current PIN is required').isNumeric().exists(),
  check('newPin', 'New PIN is required').isNumeric().exists(),
];

const keyValidation = [
  check('key', 'Key is required').isNumeric().exists(),
];

const permissionValidation = [
  check('wallet_id', 'Wallet ID is required').not().isEmpty(),
  check('role_id', 'Please include a valid role ID').isInt().not().isEmpty(),
  check('user_role', 'User Role is required').isString().not().isEmpty(),
];

// Rate limiter middleware for login
const loginRateLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 3, // Limit each IP to 3 requests per windowMs
  headers: false,
});

// User routes
router.get('/', validateToken, authController.getUser); // Get current user's data
router.get('/pin', validateToken, authController.getUserPin); // Get current user's PIN

// POST: User login
router.post(
  '/login',
  loginRateLimiter,
  emailPasswordValidation,
  authController.login,
);

// POST: Create or update user PIN
router.post(
  '/pin',
  pinValidation,
  validateToken,
  authController.createUserPin, // Can also handle creating or validating a PIN
);

// PUT: Update existing user PIN
router.put(
  '/pin',
  updatePinValidation,
  validateToken,
  authController.updateUserPin,
);

// POST: Create a farmer key
router.post(
  '/key',
  keyValidation,
  validateFarmer,
  createFarmerKey,
);

// GET: Refresh user authentication token
router.get(
  '/refresh',
  [
    check('x-auth-token', 'Authentication token is required').isJWT().exists(),
  ],
  authController.refreshToken,
);

// POST: Update user permissions
router.post(
  '/permission',
  permissionValidation,
  validateToken,
  authController.updateUserPermission,
);

module.exports = router;