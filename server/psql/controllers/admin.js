const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { validationResult } = require('express-validator');
const { WelcomeMail } = require('../../mails');
const users = require('../models/users');
const wallet = require('../models/wallet');
const userController = require('./users');
const CryptoJS = require("crypto-js");
const pinHash = require('sha256');
const sendEmail = require('../../helpers/sendMail');

/**
 * @function createAdminUser
 * @description Registers a new admin user, generates a wallet ID, and sends a welcome email.
 * @param {Object} req - The request object.
 * @param {Object} res - The response object.
 * @returns {Object} JSON response with user details or error message.
 */
exports.createAdminUser = async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { email, password } = req.body;
  const name = email.split('@')[0];
  const wallet_id = userController.generateUniqueId(32);

  try {
    const userExists = await users.checkUserExists(email);
    if (userExists && userExists.length) {
      return res.status(403).json({ msg: 'userExists' });
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = bcrypt.hashSync(String(password), salt);

    const input = {
      name,
      email,
      password: hashedPassword,
      wallet_id
    };

    await users.createUser(input);
    await users.createPermission({ wallet_id, role_id: 1 });

    const token = await users.genToken(input);
    await users.createUserToken(token);

    await sendEmail(email, WelcomeMail(name));

    return res.json({ user: email, token, msg: 'admin user registered' });
  } catch (error) {
    console.error(error.message);
    return res.status(500).json({ msg: 'Internal server error while creating admin user' });
  }
};

/**
 * @function updateUserPermission
 * @description Updates the permission of a user based on wallet ID and role.
 * @param {Object} req - The request object.
 * @param {Object} res - The response object.
 * @returns {Object} JSON response with update status or error message.
 */
exports.updateUserPermission = async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { wallet_id, user_role, role_id } = req.body;

  try {
    const userExists = await users.checkUserExists(wallet_id);
    if (!userExists || !userExists.length) {
      return res.status(403).json({ msg: 'userNotExists' });
    }
    if (user_role === "admin" || role_id == 1) {
      return res.status(404).json({ msg: 'forbidden Request' });
    }

    await users.updatePermission({ role_id, wallet_id });
    return res.json({ msg: 'user permission updated' });
  } catch (error) {
    console.error(error.message);
    return res.status(500).json({ msg: 'Internal server error while updating user permission' });
  }
};

/**
 * @function getUserPermission
 * @description Retrieves the permissions of a user based on wallet ID.
 * @param {Object} req - The request object.
 * @param {Object} res - The response object.
 * @returns {Object} JSON response with user permissions or error message.
 */
exports.getUserPermission = async (req, res) => {
  try {
    const wallet_id = req.user.wallet_id;
    const user = await users.getUserPermission(wallet_id);
    return res.status(200).json(user);
  } catch (err) {
    console.error(err.message);
    return res.status(500).send('Internal server error while getting user permission');
  }
};

/**
 * @function getUserPermissions
 * @description Retrieves all user permissions.
 * @param {Object} req - The request object.
 * @param {Object} res - The response object.
 * @returns {Object} JSON response with all user permissions or error message.
 */
exports.getUserPermissions = async (req, res) => {
  try {
    const permissions = await users.getUserPermissions();
    return res.status(200).json(permissions);
  } catch (err) {
    console.error(err.message);
    return res.status(500).send('Internal server error while getting user permissions');
  }
};

/**
 * @function getUserRoles
 * @description Retrieves all user roles.
 * @param {Object} req - The request object.
 * @param {Object} res - The response object.
 * @returns {Object} JSON response with all user roles or error message.
 */
exports.getUserRoles = async (req, res) => {
  try {
    const roles = await users.getUserRoles();
    return res.status(200).json(roles);
  } catch (err) {
    console.error(err.message);
    return res.status(500).send('Internal server error while getting user roles');
  }
};

/**
 * @function getBuyers
 * @description Retrieves all buyers.
 * @param {Object} req - The request object.
 * @param {Object} res - The response object.
 * @returns {Object} JSON response with all buyers or error message.
 */
exports.getBuyers = async (req, res) => {
  try {
    const buyers = await users.getBuyers();
    return res.status(200).json(buyers);
  } catch (err) {
    console.error(err.message);
    return res.status(500).send('Internal server error while getting buyers');
  }
};

/**
 * @function createUserRole
 * @description Creates a new user role.
 * @param {Object} req - The request object.
 * @param {Object} res - The response object.
 * @returns {Object} JSON response with created role or error message.
 */
exports.createUserRole = async (req, res) => {
  const { role } = req.body;
  if (!['admin', 'buyer'].includes(role)) {
    return res.status(403).json({ msg: 'userRoleInvalid' });
  }

  try {
    const userRole = await users.createUserRole(role);
    return res.status(200).json(userRole);
  } catch (err) {
    console.error(err.message);
    return res.status(500).send('Internal server error while creating user role');
  }
};

/**
 * @function updateUserRole
 * @description Updates an existing user role.
 * @param {Object} req - The request object.
 * @param {Object} res - The response object.
 * @returns {Object} JSON response with updated role or error message.
 */
exports.updateUserRole = async (req, res) => {
  try {
    const updatedRole = await users.updateUserRole(req.body);
    return res.status(200).json(updatedRole);
  } catch (err) {
    console.error(err.message);
    return res.status(500).send('Internal server error while updating user role');
  }
};

/**
 * @function login
 * @description Authenticates a user and returns a JWT token if successful.
 * @param {Object} req - The request object.
 * @param {Object} res - The response object.
 * @returns {Object} JSON response with token and user roles or error message.
 */
exports.login = async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { email, password } = req.body;

  try {
    const user = await users.getUserDetailsByEmail(email);
    if (!user || !user.length) {
      return res.status(400).json({ errors: [{ msg: 'User not registered yet' }] });
    }

    if (user[0].id != 1) {
      return res.status(403).json({ errors: [{ msg: 'User ID flagged. Contact admin for assistance.' }] });
    }

    const roleResponse = await users.getUserPermission(user[0].wallet_id);
    if (!roleResponse || !roleResponse.length || roleResponse[0].role === 'null' || roleResponse[0].role !== 'admin') {
      return res.status(403).json({ msg: 'forbidden Request' });
    }

    const isMatch = await bcrypt.compare(String(password), user[0].password);
    if (!isMatch) {
      return res.status(400).json({ errors: [{ msg: 'Invalid credentials' }] });
    }

    const isFlagged = await users.isWalletIdFlagged(user[0].wallet_id);
    if (isFlagged[0].flag === 1) {
      return res.status(403).json({ errors: [{ msg: 'User flagged. Contact admin for assistance.' }] });
    }

    const token = await users.updateToken(user[0].wallet_id);
    const pinSet = user[0].pin ? true : false;
    const userRoles = roleResponse.map(el => el.role);

    return res.json({ token, pin: pinSet, user_roles: userRoles[0] });
  } catch (error) {
    console.error(error.message);
    return res.status(500).json({ msg: 'Internal server error during login' });
  }
};

/**
 * @function createOrUpdateAdminPin
 * @description Creates or updates the admin PIN for a user.
 * @param {Object} req - The request object.
 * @param {Object} res - The response object.
 * @returns {Object} JSON response with PIN status or error message.
 */
exports.createOrUpdateAdminPin = async (req, res) => {
  const wallet_id = req.admin.wallet_id;

  try {
    const pinSet = await users.fetchUserPin(wallet_id);
    const existingPin = pinSet.length > 0 ? pinSet[0].pin : null;

    const str = req.body.pin + wallet_id + req.admin.user;
    const pinStr = req.body.pin + req.admin.user;
    const pn = pinHash(str);
    const pword = pinHash(pinStr);
    const encryptedPin = CryptoJS.AES.encrypt(pn, pword).toString();

    if (existingPin && existingPin !== 'null') {
      await users.updateUserPin({ wallet_id, pin: encryptedPin });
      return res.json({ msg: 'Admin PIN updated' });
    } else {
      await users.setUserPin({ wallet_id, pin: encryptedPin });
      return res.json({ msg: 'Admin PIN created' });
    }
  } catch (error) {
    console.error(error.message);
    return res.status(500).json({ msg: 'Internal server error while creating/updating admin PIN' });
  }
};

/**
 * @function getAdminPin
 * @description Retrieves the admin PIN for a user.
 * @param {Object} req - The request object.
 * @param {Object} res - The response object.
 * @returns {Object} JSON response with PIN or error message.
 */
exports.getAdminPin = async (req, res) => {
  try {
    const response = await users.fetchUserPin(req.admin.wallet_id);
    const pin = response[0]?.pin;

    if (!pin || pin === 'null') {
      return res.status(401).json({ msg: 'pinNotSet' });
    }

    return res.json({ pin, msg: 'pinSet' });
  } catch (error) {
    console.error(error.message);
    return res.status(500).json({ msg: 'Internal server error while getting admin PIN' });
  }
};

/**
 * @function getAdmin
 * @description Retrieves the details of an admin user based on wallet ID.
 * @param {Object} req - The request object.
 * @param {Object} res - The response object.
 * @returns {Object} JSON response with admin details or error message.
 */
exports.getAdmin = async (req, res) => {
  try {
    const wallet_id = req.admin.wallet_id;
    const user = await users.getDetailsByWalletId(wallet_id);
    return res.status(200).json(user);
  } catch (err) {
    console.error(err.message);
    return res.status(500).send('Internal server error while getting admin details');
  }
};

/**
 * @function deleteUser
 * @description Deletes a user based on email and wallet ID.
 * @param {Object} req - The request object.
 * @param {Object} res - The response object.
 * @returns {Object} JSON response with deletion status or error message.
 */
exports.deleteUser = async (req, res) => {
  const email = req.body.email;

  try {
    const adminDetails = await users.getDetailsByWalletId(req.admin.wallet_id);
    const adminEmail = adminDetails[0].email;

    const userDetails = await users.getUserDetailsByEmail(email);
    const userEmail = userDetails[0].email;
    const wallet_id = userDetails[0].wallet_id;

    if (adminEmail === email && userEmail === email) {
      return res.status(403).json({ msg: 'unauthorized delete admin' });
    }

    await Promise.all([
      users.deleteFromUserPermission(wallet_id),
      users.deleteUserToken(wallet_id),
      wallet.deleteCryptoBalance(wallet_id),
      wallet.deleteWallet(wallet_id),
      wallet.deleteBTC(wallet_id),
      wallet.deleteEVM(wallet_id),
      wallet.deleteWIF(wallet_id),
      users.deleteUser(email)
    ]);

    return res.status(200).json({ user: email, msg: "deleted" });
  } catch (err) {
    console.error(err.message);
    return res.status(500).send('Internal server error while deleting user');
  }
};

/**
 * @function deleteFarmer
 * @description Deletes a farmer based on wallet ID.
 * @param {Object} req - The request object.
 * @param {Object} res - The response object.
 * @returns {Object} JSON response with deletion status or error message.
 */
exports.deleteFarmer = async (req, res) => {
  const wallet_id = req.body.wallet_id;

  try {
    const user = await farmer.deleteFarmer(wallet_id);
    return res.status(200).json(user);
  } catch (err) {
    console.error(err.message);
    return res.status(500).send('Internal server error while deleting farmer');
  }
};
