const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { validationResult } = require('express-validator');
const { WelcomeMail } = require('../../mails');
const users = require('../models/users');
const transactions = require('../models/transactions');
const sendEmail = require('../../helpers/sendMail');
const nodemailer = require('nodemailer');
const config = require('../config');
const path = require('path');
const he = require('he');

const createResponse = (status, message, data) => {
  const response = {
    status,
    message,
  };

  if (data !== null && data !== undefined) {
    response.data = data;
  }

  return response;
};

exports.generateUniqueId = function (length) {
  const characters = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  let id = '';
  for (let i = 0; i < length; i++) {
    const randomIndex = Math.floor(Math.random() * characters.length);
    id += characters[randomIndex];
  }
  return id;
}

exports.createUser = async (req, res) => {
  // Validate request
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json(createResponse(400, 'Validation error', errors.array()));
  }

  const { email, password } = req.body;
  const name = email.split('@')[0];
  const role = "buyer";
  const wallet_id = this.generateUniqueId(32);
  const otp = this.generateOTP(4);

  try {
    const userExists = await users.checkUserExists(email);
    if (userExists && userExists.length) {
      return res.status(403).json(createResponse(403, 'User already exists.'));
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(String(password), salt);

    const userInput = {
      name,
      email,
      password: hashedPassword,
      wallet_id,
      role
    };

    await users.createUser(userInput);
    await users.createBuyer(wallet_id);

    const token = await users.genToken(wallet_id);
    await users.createUserToken(token);

    const email_ver_token = await users.genVerToken(email);
    await users.createEmailToken({
      email: email_ver_token.email,
      expiry: email_ver_token.expiry,
      token: otp
    });

    const verificationEmailContent = createVerificationEmail(name, otp);

    try {
      await sendEmail(email, verificationEmailContent);
      return res.status(201).json(createResponse(201, "User created and verification email sent."));
    } catch (emailError) {
      console.error('Email sending failed:', emailError);
      return res.status(500).json(createResponse(500, "User created, but failed to send verification email."));
    }

  } catch (error) {
    console.error('Internal server error:', error.message);
    return res.status(500).json(createResponse(500, 'Internal server error while creating user'));
  }
};

exports.createProfilePicture = async (req, res) => {
  const errors = validationResult(req);

  if (!errors.isEmpty()) {
    return res.status(400).json(createResponse(400, 'Validation error', errors.array()));
  }

  //const { wallet_id, address, tx_hash, mode, value, fiat} = req.body;
  try {
    const usr = req.user, adm = req.admin;
    let walletid;
    if (usr) {
      walletid = usr.wallet_id;
    }
    else {
      walletid = adm.wallet_id
    }
    if (req.body.wallet_id !== walletid) {
      return res.status(403).json(createResponse(403, 'User wallet ID mismatch.'));
    }
    //req.body.wallet_id == walletid;  
    const response = await users.createUserProfilePicture(req.body);
    return res.status(200).json(createResponse(200, 'Profile picture updated successfully', response));
  } catch (error) {
    console.error('createProfilePicture', error.message);
    return res.status(500).json(createResponse(500, 'Internal server error'));
  }
};

exports.createEmailToken = async (req, res) => {
  const errors = validationResult(req);

  if (!errors.isEmpty()) {
    return res.status(400).json(createResponse(400, 'Validation error', errors.array()));
  }

  //const { wallet_id, address, tx_hash, mode, value, fiat} = req.body;
  try {
    const usr = req.user, adm = req.admin;
    let walletid;
    if (usr) {
      walletid = usr.wallet_id;
    }
    else {
      walletid = adm.wallet_id
    }

    const curr_user_email = await users.getDetailsByWalletId(walletid);
    const token = await users.genVerToken(curr_user_email[0].email);
    await users.createEmailToken(token);
    //req.body.wallet_id == walletid;  
    const response = {
      token: token,
      status: "created"
    }
    return res.status(200).json(createResponse(200, 'Email token created successfully', response));
  } catch (error) {
    console.error('createEmailToken', error.message);
    return res.status(500).json(createResponse(500, 'Internal server error'));
  }
};

exports.sendVerification = async (req, res) => {
  try {
    //let testAccount = await nodemailer.createTestAccount();
    const { token, email } = req.body;
    const fetch_user = await users.fetchUserName(email);
    const user = fetch_user[0].name;
    let transporter = nodemailer.createTransport({
      host: config.SMTP_HOST,
      port: config.SMTP_PORT,
      secure: true,
      auth: {
        user: config.SMTP_USER,
        pass: config.SMTP_PW,
      },
    });
    const AUTH_URL = `http://102.133.149.187/backend/users/verify`;//http://102.133.149.187/backend/users/verify//localhost:9000/axkledger/v1/api/users/verify
    const auth_link = `${req.protocol}://${req.get('host')}${req.originalUrl}/verify/:${he.encode(token)}`;
    const link = `${AUTH_URL}/:${he.encode(token)}`;
    console.log(auth_link + " : " + link);
    // send mail with defined transport object
    let info = await transporter.sendMail({
      from: `${config.FROM_NAME}👻 <${config.FROM_EMAIL}>`,//'"Verification 👻" <no-reply@doeremi.com>', // sender address
      to: email, //"nostrakelvin@gmail.com" // list of receivers
      subject: "Please Verify Your Afrikabal Account ✔", // Subject line
      text: "Hello " + he.encode(user), // plain text body
      html: "Hello " + he.encode(user) + ",<br> You've successfully created an afrikabal account from this email.<br><a href=" + link + ">Click here to verify your email</a>", // html body
    });
    console.log("Message sent: %s", info.messageId);
    // Message sent: <b658f8ca-6296-ccf4-8306-87d57a0b4321@example.com>

    // Preview only available when sending through an Ethereal account
    console.log("Preview URL: %s", nodemailer.getTestMessageUrl(info));
    // Preview URL: https://ethereal.email/message/WaQKMgKddxQDoou...
    return res.status(200).json(createResponse(200, 'Verification email sent successfully', info));
    //return successResponse(200, info, 'sent')
  } catch (error) {
    //console.error('error -> ', logStruct('sendVerfication', error))
    //return errorResponse(error.status, error.message);
    console.error(error.message);
    return res.status(500).json(createResponse(500, 'Internal server error while sending verification email'));
  }
};

exports.sendResetEmailToken = async (req, res) => {
  try {
    const userExists = await users.checkUserExists(req.body.email);
    if (!userExists.length) {
      return res.status(400).json(createResponse(400, 'User does not exist.'));
    }

    const user = userExists[0];
    const token = await users.genVerToken(req.body.email);
    await users.createEmailToken(token);

    let transporter = nodemailer.createTransport({
      host: config.SMTP_HOST,
      port: config.SMTP_PORT,
      secure: true,
      auth: {
        user: config.SMTP_USER,
        pass: config.SMTP_PW,
      },
    });

    const otp = this.generateOTP(4);

    console.log('User:', user);

    const emailContent = createResetPasswordEmail(user.name, otp);

    await transporter.sendMail({
      from: `"Support" <${config.FROM_EMAIL}>`,
      to: req.body.email,
      subject: "Afrikabal - Password Reset Request",
      html: emailContent,
      attachments: [
        {
          filename: 'logo.png',
          path: path.join(__dirname, '../public/images/logo.png'),
          cid: 'logo',
        },
      ],
    });

    await users.resetPassword({ email: req.body.email, token: token.token });
    return res.status(200).json(createResponse(200, 'Reset password email sent successfully'));
  } catch (error) {
    console.error('Error sending reset email:', error.message);
    return res.status(500).json(createResponse(500, 'Internal server error'));
  }
};

exports.updateProfile = async (req, res) => {
  try {
    const userExists = await users.checkUserExists(req.user.wallet_id);
    if (!userExists.length) {
      return res.status(400).json(createResponse(400, 'User does not exist.'));
    }

    const updatedUser = await users.updateUserProfile(req.body);
    return res.status(200).json(createResponse(200, 'User profile updated successfully', updatedUser));
  } catch (error) {
    console.error('Error updating profile:', error.message);
    return res.status(500).json(createResponse(500, 'Internal server error'));
  }
};

exports.updatePassword = async (req, res) => {
  try {
    const userExists = await users.checkUserExists(req.body.email);
    if (userExists && userExists.length) {
      const salt = await bcrypt.genSalt(10);
      const _password = bcrypt.hashSync(String(req.body.password), salt);
      const response = await users.updatePassword({ email: req.body.email, password: _password });
      return res.status(204).json(createResponse(204, 'Password updated successfully'));
    }
    else {
      return res.status(403).json(createResponse(403, 'User not registered.'));
    }
  } catch (error) {
    console.error(error.message);
    return res.status(500).json(createResponse(500, 'Internal server error'));
  }
};


exports.verifyToken = async (req, res) => {
  try {
    var data = {}, token = {};
    const response = await users.verifyEmailToken(req.params.token);
    if (response.message == "error" || response.valid == false || response.message == "expired") {
      return res.status(403).json(createResponse(403, "Token invalid or expired"));
    }

    token.token = response.token;
    data.email = response.email;
    token.email = response.email;
    data.wallet_id = response.wallet_id;
    data.verified = 1;
    token.used = 1;
    await users.verifyEmailTokenDb(token);
    await users.verifyEmail(data);
    return res.status(202).json(createResponse(202, 'Verified', response));
  } catch (error) {
    console.error(error.message);
    return res.status(500).json(createResponse(500, error.message));
  }
};

exports.verifyResetToken = async (req, res) => {
  try {
    const response = await users.verifyEmailToken(req.params.token);
    if (response.message == "error" || response.valid == false || response.message == "expired") {
      return res.status(403).json(createResponse(403, "Token invalid or expired"));
    }
    let data = {
      email: response.email,
      token: response.token
    }
    req.body.email = response.email;
    await users.verifyEmailTokenDb(data);
    return res.status(202).json(createResponse(202, 'Verified', response));
  } catch (error) {
    console.error(error.message);
    return res.status(500).json(createResponse(500, error.message));
  }
};


exports.resetPassword = async (req, res) => {
  try {
    const userExists = await users.checkUserExists(req.body.email);
    if (userExists && userExists.length) {
      const _salt = await bcrypt.genSalt(10);
      const new_pwd = bcrypt.hashSync(String(req.body.password), _salt);
      const response = await users.setPassword({ email: req.body.email, token: req.params.token, password: new_pwd });
      return res.status(204).json(createResponse(204, 'Password was reset successfully', response));
    }
    else {
      return res.status(403).json(createResponse(403, 'User not registered'));
    }
  } catch (error) {
    console.error(error.message);
    return res.status(500).json(createResponse(500, error.message));
  }
};


exports.changePassword = async (req, res) => {
  try {
    const userExists = await users.checkUserExists(req.user.wallet_id);
    if (userExists && userExists.length) {
      const curr_pwd = req.body.password;
      const old_pwd = await users.fetchUserPassword(req.user.wallet_id);
      let new_pwd = req.body.new_password;
      const isMatch = await bcrypt.compare(String(curr_pwd), old_pwd[0].password);
      if (!isMatch) {
        return res.status(400).json(createResponse(400, 'Incorrect current password'));
      }
      const isUnique = await bcrypt.compare(String(new_pwd), old_pwd[0].password);
      if (isUnique) {
        return res.status(400).json(createResponse(400, 'New password is not unique'));
      }
      const _salt = await bcrypt.genSalt(10);
      new_pwd = bcrypt.hashSync(String(new_pwd), _salt);
      const response = await users.changePassword({ wallet_id: req.user.wallet_id, password: new_pwd });
      return res.status(204).json(createResponse(204, 'Password change success', response));
    }
    else {
      return res.status(403).json(createResponse(403, 'User not registered'));
    }
  } catch (error) {
    console.error(error.message);
    return res.status(500).json(createResponse(500, error.message));
  }
};

exports.getUserProfile = async (req, res) => {
  try {
    const wallet_id = req.user.wallet_id;
    console.log(wallet_id);
    const profile = await users.fetchUserProfile(wallet_id);
    return res.status(200).json(createResponse(200, 'Profile fetched', profile));
  } catch (err) {
    console.error(err.message);
    return res.status(500).json(createResponse(500, 'Internal server error fetching user profile'));
  }
};

exports.getUserTransactions = async (req, res) => {
  try {
    const wallet_id = req.user.wallet_id;
    console.log(wallet_id);
    const transactionsData = await transactions.getTransactionByWalletId(wallet_id);
    return res.status(200).json(createResponse(200, 'Transactions fetched', transactionsData));
  } catch (err) {
    console.error(err.message);
    return res.status(500).json(createResponse(500, 'Internal server error fetching user transactions'));
  }
};

exports.getUserTransactionDetails = async (req, res) => {
  try {
    const hash = req.body.hash;
    console.log(hash);
    const transactionsData = await transactions.getTransactionByHash(hash);
    return res.status(200).json(createResponse(200, 'Transaction details fetched', transactionsData));
  } catch (err) {
    console.error(err.message);
    return res.status(500).json(createResponse(500, 'Internal server error fetching user transactions'));
  }
};

exports.getUserCompleteTransactions = async (req, res) => {
  try {
    const wallet_id = req.user.wallet_id;
    console.log(wallet_id);
    const transactionsData = await transactions.getCompletedTxs(wallet_id);
    return res.status(200).json(createResponse(200, 'Completed transactions fetched', transactionsData));
  } catch (err) {
    console.error(err.message);
    return res.status(500).json(createResponse(500, 'Internal server error fetching complete transactions'));
  }
};


exports.getUserPendingTransactions = async (req, res) => {
  try {
    const wallet_id = req.user.wallet_id;
    console.log(wallet_id);
    const transactionsData = await transactions.getPendingTxsUser(wallet_id);
    return res.status(200).json(createResponse(200, 'Pending transactions fetched', transactionsData));
  } catch (err) {
    console.error(err.message);
    return res.status(500).json(createResponse(500, 'Internal server error fetching pending transactions'));
  }
};


exports.generateOTP = (length) => {
  const characters = '0123456789';
  let lot_num = '';
  for (let i = 0; i < length; i++) {
    const randomIndex = Math.floor(Math.random() * characters.length);
    lot_num += characters[randomIndex];
  }
  //let date = moment().format('YYYY/MM/DD');
  //console.log(date);
  return lot_num;
}

exports.createEmailOTP = async (req, res) => {
  const errors = validationResult(req);

  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }
  //const { wallet_id, address, tx_hash, mode, value, fiat} = req.body;
  try {
    const usr = req.user, adm = req.admin;
    let walletid;
    if (usr) {
      walletid = usr.wallet_id;
    }
    else {
      walletid = adm.wallet_id
    }
    const curr_user_email = await users.getDetailsByWalletId(walletid);
    const token = await users.genVerToken(curr_user_email[0].email);
    let otp = generateOTP(6);
    token.token = otp;
    await users.createEmailToken({ email: curr_user_email[0].email, expiry: token.expiry, token: otp });
    //req.body.wallet_id == walletid;  
    const response = {
      token: token,
      status: "created"
    }
    return res.status(200).json(createResponse(200, 'OTP created', response));
  } catch (error) {
    console.error('createEmailOTP', error.message);
    return res.status(500).json(createResponse(500, error.message));
  }
};

exports.verifyOTP = async (req, res) => {
  try {
    var data = {}, token = {};
    const response = await users.getOtpToken(req.params.otp);
    var time_now = Math.floor(Date.now() / 1000);
    const user_wid = await users.getUserDetailsByEmail(response[0].email);
    if (response.length <= 0 || user_wid.length <= 0 || response[0].expiry < time_now) {
      return res.status(403).json(createResponse(403, "OTP invalid or expired"));
    }
    token.token = response[0].token;
    data.email = response[0].email;
    token.email = response[0].email;
    data.wallet_id = user_wid[0].wallet_id;
    data.verified = 1;
    token.used = 1;
    await users.verifyEmailTokenDb(token);
    await users.verifyEmail(data);
    return res.status(202).json(createResponse(202, 'OTP verified', response));
  } catch (error) {
    console.error(error.message);
    return res.status(500).json(createResponse(500, error.message));
  }
};

const createVerificationEmail = (name, otp) => {
  const today = new Date().toLocaleDateString('en-US', {
    weekday: 'long', year: 'numeric', month: 'long', day: 'numeric'
  });

  const currentYear = new Date().getFullYear();

  return {
    subject: "Welcome to Afrikabal - Account Verification",
    text: `Dear ${name}, your OTP for account verification is ${otp}.`,
    html: `
      <div style="font-family: 'Roboto', Arial, sans-serif; background-color: #f4f4f4; margin: 0; padding: 0;">
        <style>
          @import url('https://fonts.googleapis.com/css2?family=Roboto:wght@400;500;700&display=swap');
        </style>
        <div style="background: linear-gradient(135deg, #A1D36C, #eaf7e4); color: #2C3E50; padding: 20px; border-radius: 10px 10px 10px 10px; box-shadow: 0 4px 10px rgba(0,0,0,0.1); text-align: center;">
          <img src="cid:logo" alt="Afrikabal Logo" style="width: 150px; height: auto; margin-bottom: 10px;" />
          <h2 style="font-size: 24px; font-weight: 600; margin: 0;">Empowering Farmers, Transforming Lives</h2>
          <p style="font-size: 14px; color: #95A5A6; margin-top: 5px;">${today}</p>
        </div>    
  
        <div style="background-color: white; padding: 30px; border-radius: 12px; margin: 30px auto; max-width: 600px; box-shadow: 0 6px 12px rgba(0,0,0,0.1);">
          <h1 style="color: #2C3E50; font-size: 28px; margin-bottom: 15px;">Dear ${name},</h1>
          <p style="font-size: 16px; color: #34495E; line-height: 1.6;">
            We are thrilled to have you join Afrikabal. To verify your account, please use the One-Time Password (OTP) provided below:
          </p>
          
          <div style="background-color: #eaf7e4; border-radius: 10px; padding: 20px; margin: 25px 0; text-align: center; border: 3px solid #A1D36C;">
            <h2 style="font-size: 40px; font-weight: 700; color: #A1D36C; margin: 0;">${otp}</h2>
          </div>
          
          <p style="font-size: 16px; color: #34495E;">Please enter this OTP in the Afrikabal app to complete your registration. If you did not request this verification, kindly disregard this email.</p>

          <!-- <a href="https://afrikabal.com/verify" style="background-color: #A1D36C; color: white; text-decoration: none; padding: 12px 25px; border-radius: 5px; display: inline-block; font-size: 16px; font-weight: bold; margin-top: 20px; text-align: center;">Verify Now</a> -->

          <p style="font-size: 14px; color: #7f8c8d; margin-top: 25px;">Note: Your OTP is valid for a limited time. Ensure to use it promptly.</p>

          <p style="margin-top: 20px; font-size: 16px; color: #34495E;">To learn more about our services, visit our website: <a href="https://www.afrikabal.org" style="color: #A1D36C; text-decoration: underline;">Afrikabal.org</a></p>
        </div>
  
        <footer style="margin-top: 40px; font-size: 12px; color: #95a5a6; text-align: center; padding: 20px 0;">
          <p>&copy; ${currentYear} Afrikabal. All rights reserved.</p>
          <div style="margin-top: 10px;">
            <a href="#" style="color: #A1D36C; text-decoration: none; padding: 5px 10px;">Privacy Policy</a> | 
            <a href="#" style="color: #A1D36C; text-decoration: none; padding: 5px 10px;">Terms of Service</a> | 
            <a href="mailto:support@afrikabal.com" style="color: #A1D36C; text-decoration: none; padding: 5px 10px;">Contact Us</a>
          </div>
          <div style="margin-top: 20px;">
            <a href="https://www.linkedin.com/company/afrikabal" style="margin: 0 10px;">
              <img src="https://img.icons8.com/ios-filled/50/A1D36C/linkedin-circled.png" alt="LinkedIn" style="width: 30px; height: 30px;" />
            </a>
            <!-- 'll uncomment when got it -->
            <!-- <a href="https://twitter.com/afrikabal" style="margin: 0 10px;">
              <img src="https://img.icons8.com/ios-filled/50/A1D36C/twitter-circled.png" alt="Twitter" style="width: 30px; height: 30px;" />
            </a> -->
            <a href="https://instagram.com/afrikabal" style="margin: 0 10px;">
              <img src="https://img.icons8.com/ios-filled/50/A1D36C/instagram-new.png" alt="Instagram" style="width: 30px; height: 30px;" />
            </a>
          </div>
        </footer>
      </div>
    `,
  };
};

const createResetPasswordEmail = (name, resetCode) => {
  const today = new Date().toLocaleDateString('en-US', {
    weekday: 'long', year: 'numeric', month: 'long', day: 'numeric'
  });

  const currentYear = new Date().getFullYear();

  return `
      <div style="font-family: 'Roboto', Arial, sans-serif; background-color: #f4f4f4; margin: 0; padding: 0;">
        <style>
          @import url('https://fonts.googleapis.com/css2?family=Roboto:wght@400;500;700&display=swap');
        </style>
        <div style="background: linear-gradient(135deg, #A1D36C, #eaf7e4); color: #2C3E50; padding: 20px; border-radius: 10px 10px 0 0; box-shadow: 0 4px 10px rgba(0,0,0,0.1); text-align: center;">
          <img src="cid:logo" alt="Afrikabal Logo" style="width: 150px; height: auto; margin-bottom: 10px;" />
          <h2 style="font-size: 24px; font-weight: 600; margin: 0;">Password Reset Request</h2>
          <p style="font-size: 14px; color: #95A5A6; margin-top: 5px;">${today}</p>
        </div>
        
        <div style="background-color: white; padding: 30px; border-radius: 12px; margin: 30px auto; max-width: 600px; box-shadow: 0 6px 12px rgba(0,0,0,0.1);">
          <h1 style="color: #2C3E50; font-size: 28px; margin-bottom: 15px;">Hello ${name},</h1>
          <p style="font-size: 16px; color: #34495E; line-height: 1.6;">
            We received a request to reset your password. To proceed, please enter the following reset code in the password reset form:
          </p>
          
          <div style="background-color: #eaf7e4; border-radius: 10px; padding: 20px; margin: 25px 0; text-align: center; border: 3px solid #A1D36C;">
            <h2 style="font-size: 40px; font-weight: 700; color: #A1D36C; margin: 0;">${resetCode}</h2>
          </div>
          
          <p style="font-size: 16px; color: #34495E;">If you did not request this password reset, please disregard this email.</p>
          
          <p style="font-size: 16px; color: #34495E;">To learn more about our services, visit our website: <a href="https://www.afrikabal.com" style="color: #A1D36C; text-decoration: underline;">Afrikabal.com</a></p>
        </div>
  
        <footer style="margin-top: 40px; font-size: 12px; color: #95a5a6; text-align: center; padding: 20px 0;">
          <p>&copy; ${currentYear} Afrikabal. All rights reserved.</p>
          <div style="margin-top: 10px;">
            <a href="#" style="color: #A1D36C; text-decoration: none; padding: 5px 10px;">Privacy Policy</a> | 
            <a href="#" style="color: #A1D36C; text-decoration: none; padding: 5px 10px;">Terms of Service</a> | 
            <a href="mailto:support@afrikabal.com" style="color: #A1D36C; text-decoration: none; padding: 5px 10px;">Contact Us</a>
          </div>
          <div style="margin-top: 20px;">
            <a href="https://www.linkedin.com/company/afrikabal" style="margin: 0 10px;">
              <img src="https://img.icons8.com/ios-filled/50/A1D36C/linkedin-circled.png" alt="LinkedIn" style="width: 30px; height: 30px;" />
            </a>
            <a href="https://instagram.com/afrikabal" style="margin: 0 10px;">
              <img src="https://img.icons8.com/ios-filled/50/A1D36C/instagram-new.png" alt="Instagram" style="width: 30px; height: 30px;" />
            </a>
          </div>
        </footer>
      </div>
    `;
};