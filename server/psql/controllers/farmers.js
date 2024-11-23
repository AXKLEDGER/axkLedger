const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { validationResult } = require('express-validator');
const { isAddress } = require("web3-validator");
const farmers = require('../models/farmers');
const CryptoJS = require("crypto-js");
const pinHash = require('sha256');

/**
 * @function generateUniqueFarmerId
 * @description Generates a unique farmer ID of specified length.
 * @param {number} length - The length of the unique ID.
 * @returns {string} A unique ID string.
 */
const generateUniqueFarmerId = (length) => {
  const characters = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  let id = '';
  for (let i = 0; i < length; i++) {
    const randomIndex = Math.floor(Math.random() * characters.length);
    id += characters[randomIndex];
  }
  return id;
};

/**
 * @function createFarmer
 * @description Creates a new farmer and their associated wallet.
 * @param {Object} req - The request object.
 * @param {Object} res - The response object.
 * @returns {Object} JSON response with registration status or error message.
 */
exports.createFarmer = async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { name, email, password, role } = req.body;
  const wallet_id = generateUniqueFarmerId(32);

  try {
    const farmerExists = await farmers.checkFarmerExists(req.user.wallet_id);
    if (farmerExists && farmerExists.length) {
      return res.status(403).json({ msg: 'Farmer already exists' });
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(String(password), salt);

    const input = { name, email, password: hashedPassword, wallet_id };
    await farmers.createFarmer(input);

    let role_id = role === "buyer" ? 3 : 2;
    if (role === "admin") {
      return res.status(404).json({ msg: 'Forbidden request' });
    }

    const checkRole = await farmers.checkUserRole(role);
    if (!checkRole || !checkRole.length) {
      await farmers.createUserRole({ role });
    }

    await farmers.createPermission({ wallet_id, role_id });
    const token = await farmers.genToken(input);
    await farmers.createUserToken(token);

    return res.json({ token, msg: 'Farmer registered' });
  } catch (error) {
    console.error('Error creating farmer:', error.message);
    return res.status(500).json({ msg: 'Internal server error while creating farmer' });
  }
};

/**
 * @function updateFarmerToken
 * @description Updates the farmer's token.
 * @param {Object} req - The request object.
 * @param {Object} res - The response object.
 * @returns {Object} JSON response with token update status or error message.
 */
exports.updateFarmerToken = async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { address } = req.body;
  if (!isAddress(address)) {
    return res.status(401).json({ msg: 'Invalid address!' });
  }

  try {
    const farmerExists = await farmers.getFarmerToken(address);
    if (!farmerExists || !farmerExists.length) {
      return res.status(403).json({ msg: 'Farmer does not exist' });
    }

    const token = farmerExists[0].token;
    const tokenExists = await farmers.getCurrentFarmerToken({ address, token });

    if (tokenExists && tokenExists.length) {
      if (farmerExists[0].wallet_id !== tokenExists[0].wallet_id) {
        return res.status(403).json({ msg: 'Farmer details mismatch' });
      }

      const timeNow = Math.floor(Date.now() / 1000);
      if (tokenExists[0].expiry <= timeNow) {
        const newToken = await farmers.genFarmerToken(address);
        await farmers.updateFarmerToken(newToken);
        return res.json({ token: newToken, msg: 'Token updated' });
      } else {
        const verifiedToken = await farmers.verifyToken(token);
        return res.json({ token: verifiedToken });
      }
    }
  } catch (error) {
    console.error('Error updating farmer token:', error.message);
    return res.status(500).json({ msg: 'Internal server error while updating farmer token' });
  }
};

/**
 * @function getFarmer
 * @description Retrieves details of a specific farmer by address.
 * @param {Object} req - The request object.
 * @param {Object} res - The response object.
 * @returns {Object} JSON response with farmer details or error message.
 */
exports.getFarmer = async (req, res) => {
  try {
    const address = req.body.address;
    const farmer = await farmers.getFarmerDetailsByAddress(address);
    return res.status(200).json(farmer);
  } catch (error) {
    console.error('Error retrieving farmer:', error.message);
    return res.status(500).send('Internal server error while retrieving farmer');
  }
};

/**
 * @function getFarmers
 * @description Retrieves a list of all farmers.
 * @param {Object} req - The request object.
 * @param {Object} res - The response object.
 * @returns {Object} JSON response with list of farmers or error message.
 */
exports.getFarmers = async (req, res) => {
  try {
    const list_farmers = await farmers.getAllFarmers();
    return res.status(200).json(list_farmers);
  } catch (error) {
    console.error('Error retrieving farmers:', error.message);
    return res.status(500).send('Internal server error while retrieving all farmers');
  }
};

/**
 * @function createFarmerKey
 * @description Creates a new key for the farmer.
 * @param {Object} req - The request object.
 * @param {Object} res - The response object.
 * @returns {Object} JSON response with key creation status or error message.
 */
exports.createFarmerKey = async (req, res) => {
  try {
    const prevKey = await farmers.getFarmerDetailsByAddress(req.body.address);
    const prevComb = prevKey[0].name + prevKey[0].wallet_id + prevKey[0].location;
    const initKey = prevKey[0].key;
    const matchKey = pinHash(prevComb);

    if (matchKey !== initKey) {
      return res.status(403).json({ msg: 'Incorrect key' });
    }

    const strKey = req.body.pin + prevComb[0].wallet_id + prevKey[0].name;
    const keyStr = req.body.pin + prevComb[0].address;
    const ky = pinHash(strKey);
    const kyword = pinHash(keyStr);

    const encrKey = CryptoJS.AES.encrypt(ky, kyword).toString();
    const initPub = CryptoJS.AES.decrypt(prevKey[0].public_key, pinHash(prevComb));
    const decrPub = initPub.toString(CryptoJS.enc.Utf8);
    const initPriv = CryptoJS.AES.decrypt(prevKey[0].private_key, pinHash(prevComb));
    const decrPriv = initPriv.toString(CryptoJS.enc.Utf8);

    const newPub = CryptoJS.AES.encrypt(decrPub, pinHash(strKey)).toString();
    const newPriv = CryptoJS.AES.encrypt(decrPriv, pinHash(strKey)).toString();

    const response = await farmers.updateFarmerKey({
      address: req.body.wallet_id,
      private_key: newPriv,
      public_key: newPub,
      key: encrKey
    });

    return res.json({ response, msg: 'Farmer key created' });
  } catch (error) {
    console.error('Error creating farmer key:', error.message);
    return res.status(500).json({ msg: 'Internal server error while creating farmer key' });
  }
};

/**
 * @function authenticateFarmer
 * @description Authenticates a farmer using their wallet ID and pin.
 * @param {Object} req - The request object.
 * @param {Object} res - The response object.
 * @returns {Object} JSON response with authentication status or error message.
 */
exports.authenticateFarmer = async (req, res) => {
  if (req.body.wallet_id !== req.farmer.wallet_id) {
    return res.status(403).json({ msg: 'Farmer wallet ID mismatch' });
  }

  if (!req.user || !req.user.wallet_id) {
    return res.status(403).json({ msg: 'Unauthorized farmer request' });
  }

  const farmerDetails = await farmers.getFarmerDetailsByAddress(req.body.wallet_id);
  const comb = req.body.pin + farmerDetails[0].wallet_id + farmerDetails[0].name;
  const combStr = req.body.pin + farmerDetails[0].address;

  const decryptedKey = CryptoJS.AES.decrypt(farmerDetails[0].key, pinHash(combStr));
  const matchKey = decryptedKey.toString(CryptoJS.enc.Utf8);

  if (matchKey !== comb) {
    return res.status(403).json({ msg: 'Incorrect key' });
  }

  const authData = {
    comb,
    address: farmerDetails[0].address,
    key: farmerDetails[0].private_key
  };

  return res.json(authData);
};
