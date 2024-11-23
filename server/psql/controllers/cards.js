const { validationResult } = require('express-validator');
const cards = require('../models/cards');

/**
 * @function createCard
 * @description Creates a new card for the user.
 * @param {Object} req - The request object.
 * @param {Object} res - The response object.
 * @returns {Object} JSON response with card creation status or error message.
 */
exports.createCard = async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  try {
    const walletid = req.user ? req.user.wallet_id : req.admin.wallet_id;

    if (req.body.wallet_id !== walletid) {
      return res.status(403).json({ msg: 'User wallet ID mismatch' });
    }

    const response = await cards.createCard(req.body);
    return res.status(200).json(response);
  } catch (error) {
    console.error('createCard', error.message);
    return res.status(error.status || 500).json({ msg: error.message || 'Internal server error' });
  }
};

/**
 * @function updateCard
 * @description Updates an existing card for the user.
 * @param {Object} req - The request object.
 * @param {Object} res - The response object.
 * @returns {Object} JSON response with card update status or error message.
 */
exports.updateCard = async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  try {
    const walletid = req.user ? req.user.wallet_id : req.admin.wallet_id;

    if (req.body.wallet_id !== walletid) {
      return res.status(403).json({ msg: 'User wallet ID mismatch' });
    }

    await cards.updateCard(req.body);
    return res.status(200).json({ card_number: req.body.card_number, msg: 'User card updated' });
  } catch (error) {
    console.error('updateCard', error.message);
    return res.status(error.status || 500).json({ msg: error.message || 'Internal server error' });
  }
};

/**
 * @function cardBalance
 * @description Retrieves the balance of a card for the user.
 * @param {Object} req - The request object.
 * @param {Object} res - The response object.
 * @returns {Object} JSON response with card balance or error message.
 */
exports.cardBalance = async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  try {
    const walletid = req.user ? req.user.wallet_id : req.admin.wallet_id;

    if (req.body.wallet_id !== walletid) {
      return res.status(403).json({ msg: 'User wallet ID mismatch' });
    }

    const response = await cards.cardBalance(req.body);
    return res.status(200).json(response);
  } catch (error) {
    console.error('cardBalance', error.message);
    return res.status(error.status || 500).json({ msg: error.message || 'Internal server error' });
  }
};

/**
 * @function updateCardBalance
 * @description Updates the balance of a user's card.
 * @param {Object} req - The request object.
 * @param {Object} res - The response object.
 * @returns {Object} JSON response with card balance update status or error message.
 */
exports.updateCardBalance = async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  try {
    const walletid = req.user ? req.user.wallet_id : req.admin.wallet_id;

    if (req.body.wallet_id !== walletid) {
      return res.status(403).json({ msg: 'User wallet ID mismatch' });
    }

    await cards.updateCardBalance(req.body);
    return res.status(200).json({ card_id: req.body.card_number, msg: 'User card balance updated' });
  } catch (error) {
    console.error('updateCardBalance', error.message);
    return res.status(error.status || 500).json({ msg: error.message || 'Internal server error' });
  }
};

/**
 * @function getCard
 * @description Retrieves a specific card by its number.
 * @param {Object} req - The request object.
 * @param {Object} res - The response object.
 * @returns {Object} JSON response with card details or error message.
 */
exports.getCard = async (req, res) => {
  try {
    const card = await cards.getCard(req.body.card_number);
    return res.status(200).json(card);
  } catch (error) {
    console.error(error.message);
    return res.status(error.status || 500).send('Internal server error while getting card by number');
  }
};

/**
 * @function getUserCards
 * @description Retrieves all cards associated with a user.
 * @param {Object} req - The request object.
 * @param {Object} res - The response object.
 * @returns {Object} JSON response with user cards or error message.
 */
exports.getUserCards = async (req, res) => {
  try {
    const walletid = req.user ? req.user.wallet_id : req.admin.wallet_id;
    const cardsList = await cards.getUserCards(walletid);
    return res.status(200).json(cardsList);
  } catch (error) {
    console.error(error.message);
    return res.status(error.status || 500).send('Internal server error while getting user cards');
  }
};

/**
 * @function getUserCard
 * @description Retrieves a specific card of the user by its number.
 * @param {Object} req - The request object.
 * @param {Object} res - The response object.
 * @returns {Object} JSON response with specific user card details or error message.
 */
exports.getUserCard = async (req, res) => {
  try {
    const walletid = req.user ? req.user.wallet_id : req.admin.wallet_id;
    const card = await cards.getUserCard({ card_number: req.body.card_number, wallet_id: walletid });
    return res.status(200).json(card);
  } catch (error) {
    console.error(error.message);
    return res.status(error.status || 500).send('Internal server error while getting card by user');
  }
};

/**
 * @function getCardBalance
 * @description Retrieves the balance of a specific card.
 * @param {Object} req - The request object.
 * @param {Object} res - The response object.
 * @returns {Object} JSON response with card balance details or error message.
 */
exports.getCardBalance = async (req, res) => {
  try {
    const cardBalance = await cards.getCardBalance(req.body);
    return res.status(200).json(cardBalance);
  } catch (error) {
    console.error(error.message);
    return res.status(error.status || 500).send('Internal server error while getting card balance');
  }
};
