const dotenv = require('dotenv');

if (process.env.NODE_ENV === 'production') {
  dotenv.config({ path: './production.env' });
} else {
  dotenv.config({ path: './local.env' });
}

module.exports = {
  PORT: process.env.PORT || 4055,
  NODE_ENV: process.env.NODE_ENV,

  // JWT configurations
  JWT_SECRET: process.env.JWT_SECRET,
  JWT_TOKEN_EXPIRES_IN: 3600000 * 24,
  JWT_FARMER_EXPIRY: 3600000 * 48,

  // Database configurations
  DB_HOST: process.env.DB_HOST,
  DB_PORT: process.env.DB_PORT,
  DB_USER: process.env.DB_USER,
  DB_PASS: process.env.DB_PASS,
  DB_NAME: process.env.DB_NAME,

  // Blockchain and escrow accounts
  ESCROW_ETH: process.env.ESCROW_ACCOUNT_ETH,
  ESCROW_BTC: process.env.ESCROW_ACCOUNT_BTC,
  ESCROW_XRP: process.env.XRP_ESCROW_ACCOUNT,
  SUPPLY_CHAIN_ADDRESS: process.env.SUPPLY_CHAIN_ADDRESS,
  LISK_PRIV_KEY: process.env.LISK_PRIV_KEY,
  PRIVATE_KEY: process.env.PRIVATE_KEY,

  // Blockchain and crypto API tokens
  BLOCKCIPHER_TOKEN: process.env.BLOCKCIPHER_TOKEN,
  TESTNET_PUSH: process.env.TESTNET_PUSH,
  TESTNET_DECODE: process.env.TESTNET_DECODE,
  TESTNET_TX: process.env.TESTNET_TX,
  TESTNET_SEND: process.env.TESTNET_SEND,
  TESTNET_API: process.env.TESTNET_API,
  COIN_MARKET_CAP: process.env.COIN_MARKET_CAP,

  // SMTP configurations
  SMTP_HOST: process.env.SMTP_HOST,
  SMTP_PORT: process.env.SMTP_PORT,
  SMTP_USER: process.env.SMTP_USER,
  SMTP_PW: process.env.SMTP_PW,
  FROM_NAME: 'Verification',
  FROM_EMAIL: process.env.SMTP_USER,

  // Support account details
  SUPPORT_USER: process.env.SUPPORT_USER,
  SUPPORT_PW: process.env.SUPPORT_PW,
  SUPPORT_EMAIL: process.env.SUPPORT_USER,
  SUPPORT_NAME: 'Support',

  // Application-specific settings
  INITIAL_BALANCE: 0
};