const dotenv = require('dotenv');

if (process.env.NODE_ENV === 'production') {
  dotenv.config({ path: './production.env' });
} else {
  dotenv.config({ path: './local.env' });
}

module.exports = {
  // Server and Port configurations
  API_PORT: process.env.API_PORT || 8000,
  BLOCKCHAIN_PORT: process.env.BLOCKCHAIN_PORT || 9000,
  NODE_ENV: process.env.NODE_ENV,

  // JWT configurations
  JWT_SECRET: process.env.JWT_SECRET,
  JWT_TOKEN_EXPIRES_IN: 3600000 * 24,
  JWT_ADM_EXPIRES_IN: 3600000 * 12,
  JWT_FARMER_EXPIRY: 3600000 * 48,
  ADM_SECRET: process.env.ADM_SECRET,

  // Admin account details
  ADMIN_EMAIL: process.env.ADMIN_EMAIL,
  ADMIN_NAME: process.env.ADMIN_NAME,
  ADMIN_WID: process.env.ADMIN_WID,
  ADMIN_PW: process.env.ADMIN_PW,

  // Database configurations
  DB_HOST: process.env.DB_HOST,
  DB_PORT: process.env.DB_PORT,
  DB_USER: process.env.DB_USER,
  DB_PASS: process.env.DB_PASS,
  DB_NAME: process.env.DB_NAME,

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