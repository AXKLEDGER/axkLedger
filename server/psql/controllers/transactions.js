const { validationResult } = require('express-validator');
const transactions = require('../models/transactions');
const { TransactionMail } = require('../../mails');
const sendEmail = require('../../helpers/sendMail');
const users = require('../models/users');

/**
 * @function getWalletIdAndName
 * @description Retrieves the wallet ID and name from the request user or admin.
 * @param {Object} req - The request object.
 * @returns {Object} An object containing walletId and name.
 */
const getWalletIdAndName = (req) => {
  const usr = req.user;
  const adm = req.admin;
  let walletId, name;

  if (usr) {
    walletId = usr.wallet_id;
    name = usr.user;
  } else if (adm) {
    walletId = adm.wallet_id;
    name = adm.user;
  }

  return { walletId, name };
};

/**
 * @function createTransaction
 * @description Creates a new transaction and returns the response.
 * @param {Object} req - The request object.
 * @param {Object} res - The response object.
 * @returns {Object} JSON response with transaction status or error message.
 */
exports.createTransaction = async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  try {
    const { walletId } = getWalletIdAndName(req);
    req.body.wallet_id = walletId;

    const response = await transactions.createTransaction(req.body);
    return res.status(200).json(response);
  } catch (error) {
    console.error('createTransaction', error.message);
    return res.status(500).json({ msg: error.message });
  }
};

/**
 * @function sendTransactionMail
 * @description Sends a transaction email to the user.
 * @param {Object} data - Transaction data.
 * @returns {Object} Status of the email sending operation.
 */
exports.sendTransactionMail = async (data) => {
  let resSend = {};
  try {
    const { wallet_id } = data;
    const user = await users.getUserEmailByWalletId(wallet_id);
    const email = user[0].email;

    await sendEmail(email, TransactionMail(data.name, data.link, data.fiat, data.crypto, data.address));

    resSend.data = data;
    resSend.status = "success";
  } catch (error) {
    console.error('sendTransactionMail', error.message);
    resSend.data = data;
    resSend.status = "error";
  }
  return resSend;
};

/**
 * @function updateTransaction
 * @description Updates transaction data.
 * @param {Object} req - The request object.
 * @param {Object} res - The response object.
 * @returns {Object} JSON response with update status or error message.
 */
exports.updateTransaction = async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  try {
    const { walletId } = getWalletIdAndName(req);
    if (req.body.wallet_id !== walletId) {
      return res.status(403).json({ msg: 'User wallet ID mismatch' });
    }

    await transactions.updateTransactionData(req.body);
    return res.status(200).json({ tx_hash: req.body.tx_hash, msg: 'Transaction updated' });
  } catch (error) {
    console.error('updateTransaction', error.message);
    return res.status(500).json({ msg: error.message });
  }
};

/**
 * @function updateTransactionHash
 * @description Updates the transaction hash.
 * @param {Object} req - The request object.
 * @param {Object} res - The response object.
 * @returns {Object} JSON response with update status or error message.
 */
exports.updateTransactionHash = async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  try {
    const { walletId } = getWalletIdAndName(req);
    if (req.body.wallet_id !== walletId) {
      return res.status(403).json({ msg: 'User wallet ID mismatch' });
    }

    await transactions.updateTransactionHash(req.body);
    return res.status(200).json({ tx_hash: req.body.tx_hash, msg: 'Transaction updated' });
  } catch (error) {
    console.error('updateTransactionHash', error.message);
    return res.status(500).json({ msg: error.message });
  }
};

/**
 * @function updateTransactionStatus
 * @description Updates the transaction status.
 * @param {Object} req - The request object.
 * @param {Object} res - The response object.
 * @returns {Object} JSON response with update status or error message.
 */
exports.updateTransactionStatus = async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  try {
    const { walletId } = getWalletIdAndName(req);
    if (req.body.wallet_id !== walletId) {
      return res.status(403).json({ msg: 'User wallet ID mismatch' });
    }

    await transactions.updateStatus(req.body);
    return res.status(200).json({ tx_hash: req.body.tx_hash, msg: 'Transaction status updated' });
  } catch (error) {
    console.error('updateTransactionStatus', error.message);
    return res.status(500).json({ msg: error.message });
  }
};

/**
 * @function getTransactionsByUser
 * @description Retrieves transactions associated with the user.
 * @param {Object} req - The request object.
 * @param {Object} res - The response object.
 * @returns {Object} JSON response with transactions or error message.
 */
exports.getTransactionsByUser = async (req, res) => {
  try {
    const { walletId } = getWalletIdAndName(req);
    const txs = await transactions.getTransactionByWalletId(walletId);
    return res.status(200).json(txs);
  } catch (err) {
    console.error(err.message);
    return res.status(500).send('Internal server error while getting transactions by user');
  }
};

/**
 * @function getAllTransactions
 * @description Retrieves all transactions for admin users.
 * @param {Object} req - The request object.
 * @param {Object} res - The response object.
 * @returns {Object} JSON response with all transactions or error message.
 */
exports.getAllTransactions = async (req, res) => {
  const adm = req.admin;
  if (!adm) {
    return res.status(403).json({ msg: 'Unauthorized Request' });
  }

  try {
    const txs = await transactions.getAllTxs();
    return res.status(200).json(txs);
  } catch (err) {
    console.error(err.message);
    return res.status(500).send('Internal server error while getting all transactions');
  }
};

/**
 * @function getTransactionByHash
 * @description Retrieves a transaction by its hash.
 * @param {Object} req - The request object.
 * @param {Object} res - The response object.
 * @returns {Object} JSON response with transaction data or error message.
 */
exports.getTransactionByHash = async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  try {
    const hash = req.params.hash;
    const tx = await transactions.getTransactionByHash(hash);
    return res.status(200).json(tx);
  } catch (err) {
    console.error(err.message);
    return res.status(500).send('Internal server error while getting transaction by hash');
  }
};

/**
 * @function getUserTransactionByHash
 * @description Retrieves a user's transaction by its hash.
 * @param {Object} req - The request object.
 * @param {Object} res - The response object.
 * @returns {Object} JSON response with user transaction data or error message.
 */
exports.getUserTransactionByHash = async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  try {
    const { walletId } = getWalletIdAndName(req);
    const tx_hash = req.params.tx_hash;
    const tx = await transactions.getTransactionByUtx({ wallet_id: walletId, tx_hash });
    return res.status(200).json(tx);
  } catch (err) {
    console.error(err.message);
    return res.status(500).send('Internal server error while getting user transaction by hash');
  }
};

/**
 * @function getUserDeposits
 * @description Retrieves the user's deposit transactions.
 * @param {Object} req - The request object.
 * @param {Object} res - The response object.
 * @returns {Object} JSON response with deposit transactions or error message.
 */
exports.getUserDeposits = async (req, res) => {
  try {
    const { walletId } = getWalletIdAndName(req);
    const deps = await transactions.getDepositsUser(walletId);
    return res.status(200).json(deps);
  } catch (err) {
    console.error(err.message);
    return res.status(500).send('Internal server error while getting user deposit transactions');
  }
};

/**
 * @function getUserTransfers
 * @description Retrieves the user's transfer transactions.
 * @param {Object} req - The request object.
 * @param {Object} res - The response object.
 * @returns {Object} JSON response with transfer transactions or error message.
 */
exports.getUserTransfers = async (req, res) => {
  try {
    const { walletId } = getWalletIdAndName(req);
    const trans = await transactions.getTransfersUser(walletId);
    return res.status(200).json(trans);
  } catch (err) {
    console.error(err.message);
    return res.status(500).send('Internal server error while getting user transfer transactions');
  }
};

/**
 * @function getTransactionsByMode
 * @description Retrieves transactions filtered by mode for admin users.
 * @param {Object} req - The request object.
 * @param {Object} res - The response object.
 * @returns {Object} JSON response with transactions by mode or error message.
 */
exports.getTransactionsByMode = async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const adm = req.admin;
  if (!adm) {
    return res.status(403).json({ msg: 'Unauthorized Request' });
  }

  try {
    const mode = req.params.mode;
    const tx_mode = await transactions.getTxsByMode(mode);
    return res.status(200).json(tx_mode);
  } catch (err) {
    console.error(err.message);
    return res.status(500).send('Internal server error while getting all transactions by mode');
  }
};

/**
 * @function getUserTransactionsByMode
 * @description Retrieves a user's transactions filtered by mode.
 * @param {Object} req - The request object.
 * @param {Object} res - The response object.
 * @returns {Object} JSON response with user transactions by mode or error message.
 */
exports.getUserTransactionsByMode = async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  try {
    const { walletId } = getWalletIdAndName(req);
    const mode = req.body.mode;
    const trans = await transactions.getUserTxsByMode({ wallet_id: walletId, mode });
    return res.status(200).json(trans);
  } catch (err) {
    console.error(err.message);
    return res.status(500).send('Internal server error while getting user transactions by mode');
  }
};
