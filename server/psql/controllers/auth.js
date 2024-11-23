const bcrypt = require('bcryptjs');
const { validationResult } = require('express-validator');
const jwt = require('jsonwebtoken');
const users = require('../models/users');
const CryptoJS = require("crypto-js");
const walletModel = require('../models/wallet');
const { hdkey } = require('@ethereumjs/wallet');
const pinHash = require('sha256');

/**
 * @desc Get user details by wallet ID
 * @route GET /api/user
 * @access Private
 */
exports.getUser = async (req, res) => {
  try {
    const walletId = req.user.wallet_id;
    const user = await users.getDetailsByWalletId(walletId);
    return res.status(200).json(user);
  } catch (error) {
    console.error(error.message);
    return res.status(500).json({ msg: 'Internal server error while fetching user details' });
  }
};

/**
 * @desc User login
 * @route POST /api/login
 * @access Public
 */
exports.login = async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { email, password } = req.body;

  try {
    const user = await users.getUserDetailsByEmail(email);

    if (!user || user.length === 0) {
      return res.status(400).json({ errors: [{ msg: 'User not registered yet' }] });
    }

    const roleResponse = await users.getUserPermission(user[0].wallet_id);

    if (!roleResponse || roleResponse.length === 0) {
      return res.status(403).json({ msg: 'Forbidden request' });
    }

    if (roleResponse[0].role.toLowerCase() === 'admin') {
      return res.status(403).json({ msg: 'Forbidden request' });
    }

    const isMatch = await bcrypt.compare(password, user[0].password);

    if (!isMatch) {
      return res.status(400).json({ errors: [{ msg: 'Invalid credentials' }] });
    }

    const isFlagged = await users.isWalletIdFlagged(user[0].wallet_id);
    if (isFlagged[0].flag === 1) {
      return res.status(403).json({ errors: [{ msg: 'User flagged, contact admin for assistance' }] });
    }

    const token = await users.updateToken(user[0].wallet_id);
    const pinSet = Boolean(user[0].pin);
    const userRoles = roleResponse.map(el => el.role);

    return res.json({ token, pinSet, userRoles: userRoles[0] });
  } catch (error) {
    console.error(error.message);
    return res.status(500).json({ msg: 'Internal server error during login' });
  }
};

/**
 * @desc Get user permissions
 * @route GET /api/user/permissions
 * @access Private
 */
exports.getUserPermission = async (req, res) => {
  try {
    const walletId = req.user.wallet_id;
    const userPermissions = await users.getUserPermission(walletId);
    return res.status(200).json(userPermissions);
  } catch (error) {
    console.error(error.message);
    return res.status(500).json({ msg: 'Internal server error while fetching user permissions' });
  }
};

/**
 * @desc Authenticate user by passphrase
 * @route POST /api/authenticate/user
 * @access Private
 */
exports.authenticateUser = async (req, res) => {
  if (req.admin) {
    return res.status(403).json({ msg: 'Unauthorized user request' });
  }

  const combination = req.body.passphrase + req.user.user;
  const passphrase = await walletModel.getWallet(req.user.wallet_id);
  const authData = {};

  if (!passphrase.length) {
    return res.status(400).json({ msg: 'Wallet not found' });
  }

  const evm = await walletModel.getEVM(req.user.wallet_id);
  const btc = await walletModel.getBTC(req.user.wallet_id);
  const matchPassword = bcrypt.compareSync(String(combination), passphrase[0].passphrase);

  if (!matchPassword) {
    return res.status(401).json({ msg: 'Invalid password' });
  }

  authData.comb = combination;
  authData.evm = evm[0] || null;
  authData.btc = btc[0] || null;
  authData.wallet = passphrase[0];

  return res.json(authData);
};

/**
 * @desc Authenticate admin by pin
 * @route POST /api/authenticate/admin
 * @access Private
 */
exports.authenticateAdmin = async (req, res) => {
  if (req.user) {
    return res.status(403).json({ msg: 'Unauthorized admin request' });
  }

  const combination = req.body.pin + req.admin.user;
  const wallet = await walletModel.getWallet(req.admin.wallet_id);
  const adminData = {};

  if (!wallet.length) {
    return res.status(400).json({ msg: 'Admin wallet not found' });
  }

  const eth = await walletModel.getEVM(req.admin.wallet_id);
  const btc = await walletModel.getBTC(req.admin.wallet_id);
  const matchPassword = bcrypt.compareSync(String(combination), wallet[0].passphrase);

  if (!matchPassword) {
    return res.status(401).json({ msg: 'Invalid password' });
  }

  adminData.comb = combination;
  adminData.evm = eth[0] || null;
  adminData.btc = btc[0] || null;
  adminData.wallet = wallet[0];

  return res.json(adminData);
};

/**
 * @desc Decrypt private key
 * @param {Object} data - Data containing wallet and combination
 * @returns {Object} - Decrypted Ethereum address and private key
 */
exports.decryptPrivKey = (data) => {
  const decryptedMnemonic = CryptoJS.AES.decrypt(data.wallet.mnemonic, pinHash(data.comb)).toString(CryptoJS.enc.Utf8);
  const walletEth = hdkey.EthereumHDKey.fromMnemonic(decryptedMnemonic, pinHash(data.comb));
  const privateKey = walletEth.getWallet().getPrivateKeyString();
  const ethAddress = walletEth.getWallet().getAddressString();

  return {
    addr: ethAddress,
    key: privateKey,
  };
};

/**
 * @desc Create user pin
 * @route POST /api/user/pin
 * @access Private
 */
exports.createUserPin = async (req, res) => {
  try {
    const pinSet = await users.fetchUserPin(req.user.wallet_id);
    const existingPin = pinSet[0]?.pin;

    if (existingPin !== 'null' && existingPin !== null) {
      return res.status(403).json({ msg: 'PIN already exists' });
    }

    const pinCombination = req.body.pin + req.user.wallet_id + req.user.user;
    const encryptedPin = CryptoJS.AES.encrypt(pinHash(pinCombination), pinHash(req.body.pin + req.user.user)).toString();
    const response = await users.setUserPin({ wallet_id: req.user.wallet_id, pin: encryptedPin });

    return res.json({ response, msg: 'User PIN created' });
  } catch (error) {
    console.error(error.message);
    return res.status(500).json({ msg: 'Internal server error while creating user PIN' });
  }
};

/**
 * @desc Get user PIN
 * @route GET /api/user/pin
 * @access Private
 */
exports.getUserPin = async (req, res) => {
  try {
    const response = await users.fetchUserPin(req.user.wallet_id);
    const pin = response[0]?.pin;

    if (!pin || pin === 'null') {
      return res.status(401).json({ msg: 'PIN not set' });
    }

    return res.json({ pin, msg: 'PIN set' });
  } catch (error) {
    console.error(error.message);
    return res.status(500).json({ msg: 'Internal server error while fetching user PIN' });
  }
};

/**
 * @desc Update user PIN
 * @route PUT /api/user/pin
 * @access Private
 */
exports.updateUserPin = async (req, res) => {
  try {
    const { user: usr, admin: adm } = req;
    const isUser = !!usr;
    const currPin = req.body.new_passphrase;
    const walletId = isUser ? usr.wallet_id : adm.wallet_id;

    if (isUser) {
      await this.authenticatePin(req, res);
    } else {
      await this.authenticatePinAdmin(req, res);
    }

    const prevPinCombination = isUser
      ? req.body.passphrase + usr.wallet_id + usr.user
      : req.body.pin + adm.wallet_id + adm.user;
    const newPinCombination = currPin + walletId + (isUser ? usr.user : adm.user);

    if (prevPinCombination === newPinCombination) {
      return res.status(403).json({ msg: 'New PIN cannot match the old PIN' });
    }

    // Hash and encrypt the new PIN
    const hashedNewPin = pinHash(newPinCombination);
    const encryptedNewPin = CryptoJS.AES.encrypt(
      hashedNewPin,
      pinHash(currPin + (isUser ? usr.user : adm.user))
    ).toString();

    // Update the user's wallet and PIN in the database
    const wallet = await walletModel.getWallet(walletId);
    if (wallet.length > 0) {
      // Update wallet keys
      const walletUpdate = {
        wallet_id: walletId,
        key: encryptedNewPin, // Placeholder for updated key logic
        passcode: bcrypt.hashSync(currPin + (isUser ? usr.user : adm.user), 10) // Hashed passphrase
      };
      await walletModel.updateWallet(walletUpdate);

      // Update BTC keys if they exist
      const btcWallet = await walletModel.getBTC(walletId);
      if (btcWallet.length > 0) {
        const prevPinHash = pinHash(prevPinCombination);
        const newWif = CryptoJS.AES.encrypt(
          CryptoJS.AES.decrypt(btcWallet[0].wif, prevPinHash).toString(CryptoJS.enc.Utf8),
          pinHash(currPin + (isUser ? usr.user : adm.user))
        ).toString();
        const newXPriv = CryptoJS.AES.encrypt(
          CryptoJS.AES.decrypt(btcWallet[0].xpriv, prevPinHash).toString(CryptoJS.enc.Utf8),
          pinHash(currPin + (isUser ? usr.user : adm.user))
        ).toString();
        const newXPub = CryptoJS.AES.encrypt(
          CryptoJS.AES.decrypt(btcWallet[0].xpub, prevPinHash).toString(CryptoJS.enc.Utf8),
          pinHash(currPin + (isUser ? usr.user : adm.user))
        ).toString();

        await walletModel.updateBTCKeys({
          wallet_id: walletId,
          wif_key: newWif,
          priv_key: newXPriv,
          pub_key: newXPub
        });
      }

      // Update XRP keys if they exist
      const xrpWallet = await walletModel.getXRPWallet(walletId);
      if (xrpWallet.length > 0) {
        const prevPinHash = pinHash(prevPinCombination);
        const newPrivKey = CryptoJS.AES.encrypt(
          CryptoJS.AES.decrypt(xrpWallet[0].privKey, prevPinHash).toString(CryptoJS.enc.Utf8),
          pinHash(currPin + (isUser ? usr.user : adm.user))
        ).toString();
        const newPubKey = CryptoJS.AES.encrypt(
          CryptoJS.AES.decrypt(xrpWallet[0].pubKey, prevPinHash).toString(CryptoJS.enc.Utf8),
          pinHash(currPin + (isUser ? usr.user : adm.user))
        ).toString();

        await walletModel.updateXRPKeys({
          wallet_id: walletId,
          new_priv: newPrivKey,
          new_pub: newPubKey
        });
      }

      // Update the user's PIN
      await users.setUserPin({
        wallet_id: walletId,
        pin: encryptedNewPin
      });

      return res.json({ msg: 'PIN updated successfully' });
    }

    return res.status(400).json({ msg: 'Wallet not found' });
  } catch (error) {
    console.error(error.message);
    return res.status(500).json({ msg: 'Internal server error while updating user PIN' });
  }
};

// Helper fx to validate pins
const validatePin = (pin, storedPin, vPin) => {
  const decryptedPin = CryptoJS.AES.decrypt(storedPin, vPin).toString(CryptoJS.enc.Utf8);
  return pin === decryptedPin;
};

/**
 * @desc Authenticate user PIN
 * @route POST /api/user/authenticatePin
 * @access Private
 */
exports.authenticatePin = async (req, res) => {
  try {
    const { user } = req;
    const storedPin = await users.fetchUserPin(user.wallet_id);
    const strPin = req.body.passphrase + user.wallet_id + user.user;
    const hPin = pinHash(strPin);
    const vPin = pinHash(req.body.passphrase + user.user);

    // Validate the pin
    if (!validatePin(hPin, storedPin[0].pin, vPin)) {
      return res.status(403).json({ msg: 'incorrect_pin' });
    }
  } catch (error) {
    console.error(error.message);
    return res.status(500).json({ msg: 'Internal server error during PIN authentication' });
  }
};

/**
 * @desc Authenticate admin PIN
 * @route POST /api/admin/authenticatePin
 * @access Private
 */
exports.authenticatePinAdmin = async (req, res) => {
  try {
    const { admin } = req;
    const storedPin = await users.fetchUserPin(admin.wallet_id);
    const strPin = req.body.pin + admin.wallet_id + admin.user;
    const hPin = pinHash(strPin);
    const vPin = pinHash(req.body.pin + admin.user);

    // Validate the pin
    if (!validatePin(hPin, storedPin[0].pin, vPin)) {
      return res.status(403).json({ msg: 'incorrect_pin' });
    }
  } catch (error) {
    console.error(error.message);
    return res.status(500).json({ msg: 'Internal server error during admin PIN authentication' });
  }
};

/**
 * @desc Refresh user token
 * @route POST /api/token/refresh
 * @access Private
 */
exports.refreshToken = async (req, res) => {
  try {
    const token = req.header('x-auth-token');
    const farmer_token = req.header('x-farmer-token');
    const admin_token = req.header('x-admin-token');
    const timeNow = Math.floor(Date.now() / 1000);

    let currToken, updateToken;

    if (!token && !farmer_token && !admin_token) {
      return res.status(403).json({ msg: 'Unauthorized request!' });
    }

    if (token) {
      currToken = await users.getCurrentTokenUser(token);
      if (!currToken || !currToken.length) {
        return res.status(401).json({ msg: 'Unexisting user jwt db!' });
      }
      const { expiration, wallet_id } = currToken[0];

      if (expiration <= timeNow) {
        const newTokenData = await users.genToken(wallet_id);
        await users.updateCurrentUserToken({ token, new_token: newTokenData.token, expiration: newTokenData.expiration });
        updateToken = await users.verifyToken(newTokenData.token);
        return res.send(updateToken);
      } else {
        return res.send(await users.verifyToken(token));
      }
    }

    // Handle admin token refresh
    if (admin_token) {
      currToken = await users.getCurrentTokenUser(admin_token);
      if (!currToken || !currToken.length) {
        return res.status(401).json({ msg: 'Unexisting admin jwt db!' });
      }
      const { expiration, wallet_id } = currToken[0];

      if (expiration <= timeNow) {
        const newTokenData = await users.genToken(wallet_id);
        await users.updateCurrentUserToken({ token, new_token: newTokenData.token, expiration: newTokenData.expiration });
        updateToken = await users.verifyToken(newTokenData.token);
        return res.send(updateToken);
      } else {
        return res.send(await users.verifyAdminToken(admin_token));
      }
    }

    // Handle farmer token refresh
    if (farmer_token) {
      const farmerTokenData = await farmers.getJWTFarmerToken(farmer_token);
      if (!farmerTokenData || !farmerTokenData.length) {
        return res.status(401).json({ msg: 'Unexisting farmer jwt db!' });
      }
      const { expiry, address, wallet_id } = farmerTokenData[0];

      if (expiry <= timeNow) {
        const payload = { farmer: { wallet_id, address } };
        const newToken = farmers.createToken(payload);
        const expiry_date = farmers.getExpiryDate(newToken.token);
        await farmers.updateFarmerToken({ address, token: newToken.token, expiry: expiry_date.data.exp });
        updateToken = await farmers.verifyToken(newToken.token);
        return res.send(updateToken);
      } else {
        return res.send(await farmers.verifyToken(farmer_token));
      }
    }

    return res.status(404).json({ msg: 'No required parameters for refreshing user token' });
  } catch (err) {
    console.error(`${err.message}: Internal auth error in token refresh controller`);
    res.status(500).json({ msg: 'Internal refresh user token error' });
  }
};

/**
 * @desc Update user role
 * @route PUT /api/user/role
 * @access Private
 */
exports.updateUserRole = async (req, res) => {
  try {
    const updatedUser = await users.updateRoleTime(req.body);
    return res.status(200).json(updatedUser);
  } catch (err) {
    console.error(err.message);
    return res.status(500).send('Internal server error updating user role time');
  }
};

/**
 * @desc Update user permissions
 * @route PUT /api/user/permissions
 * @access Private
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
    if (role_id == 1 || user_role === 'admin') {
      return res.status(404).json({ msg: 'forbidden Request' });
    }

    const input = { role_id, wallet_id };
    await users.updatePermission(input);

    return res.json({ input, msg: 'User permission updated' });

  } catch (error) {
    console.error(error.message);
    return res.status(500).json({ msg: 'Internal server error updating user permission' });
  }
};
