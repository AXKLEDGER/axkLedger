const express = require('express');
const router = express.Router();
const { check } = require('express-validator');
const { validateAdmin, validateFarmer } = require('../../middleware/auth');
const adminController = require('../../controllers/admin');
const { refreshToken } = require('../../controllers/auth');
const farmerController = require('../../controllers/farmers');
const transactions = require('../../controllers/transactions');

const emailValidation = check('email', 'Please include a valid email').isEmail();
const passwordValidation = check('password', 'Password is required').exists();
const pinValidation = check('pin', 'Pin is required').isNumeric().exists();
const walletValidation = check('wallet_id', 'Wallet ID is required').not().isEmpty();
const roleValidation = check('role', 'User Role is required').not().isEmpty();
const roleIdValidation = check('role_id', 'User Role ID is required').isInt().exists();
const addressValidation = check('address', 'Farmer address ID is required').isEthereumAddress().exists();

router.get('/', validateAdmin, adminController.getAdmin);
router.get('/buyers', validateAdmin, adminController.getBuyers);
router.get('/farmers', validateAdmin, farmerController.getFarmers);
router.get('/permissions', validateAdmin, adminController.getUserPermissions);
router.get('/pin', validateAdmin, adminController.getAdminPin);
router.get('/roles', validateAdmin, adminController.getUserRoles);
router.get('/txs', validateAdmin, transactions.getAllTransactions);

router.post(
  '/login',
  [emailValidation, passwordValidation],
  adminController.login,
);

// Create an admin user
router.post(
  '/admin',
  [
    emailValidation,
    check('password', 'Password must be at least 12 characters long and contain letters and numbers')
      .isLength({ min: 12 })
      .isAlphanumeric(),
  ],
  validateAdmin,
  adminController.createAdminUser,
);

// Update user permissions
router.post(
  '/permission',
  [
    walletValidation,
    check('role_id', 'Please include a valid role').isInt().not().isEmpty(),
    check('user_role', 'User Role is required').isString().not().isEmpty(),
  ],
  validateAdmin,
  adminController.updateUserPermission,
);

// Create a new user role
router.post(
  '/role',
  [roleValidation],
  validateAdmin,
  adminController.createUserRole,
);

// Update an existing user role
router.post(
  '/update/role',
  [roleIdValidation, roleValidation],
  validateAdmin,
  adminController.updateUserRole,
);

// Update a farmer's token
router.post(
  '/farmer/token',
  [
    check('x-admin-token', 'Admin token is required').isJWT().exists(),
    addressValidation,
  ],
  validateAdmin,
  farmerController.updateFarmerToken,
);

// Refresh a farmer's token
router.post(
  '/farmer/refresh',
  [
    check('x-farmer-token', 'Farmer token is required').exists(),
    walletValidation,
    addressValidation,
  ],
  validateAdmin,
  validateFarmer,
  refreshToken,
);

// Create or update admin PIN
router.post(
  '/pin',
  [pinValidation],
  validateAdmin,
  adminController.createOrUpdateAdminPin,
);

// Refresh admin auth token
router.get(
  '/refresh',
  [check('x-admin-token', 'Authentication token is required').isJWT().exists()],
  refreshToken,
);

// Delete a user
router.delete(
  '/del/user',
  [emailValidation],
  validateAdmin,
  adminController.deleteUser,
);

module.exports = router;
