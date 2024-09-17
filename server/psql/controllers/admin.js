
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { validationResult } = require('express-validator');
const { WelcomeMail } = require('../../mails');
const users = require('../models/users');
const userController = require('./users');
const sendEmail = require('../../helpers/sendMail');

exports.createAdminUser = async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
  
    const { email, password, role } = req.body;
    const nameMatch = email.match(/^([^@]*)@/);
    const name = nameMatch ? nameMatch[1] : null;
    //req.body.name = name;
    console.log(name);
    const wallet_id  = userController.generateUniqueId(32);
    console.log(wallet_id);
    try {
      const userExists = await users.checkUserExists(email);
      if (userExists && userExists.length) {
        return res.status(403).json({ msg : 'userExists' });
      }
      const salt = await bcrypt.genSalt(10);
      const _password = bcrypt.hashSync(String(password), salt);
      let input = {
        name : name,
        email : email,
        password : _password,
        wallet_id : wallet_id
      }

      await users.createUser(input);
      let role_id = 1;
      if (role === "buyer"){
        return res.status(404).json({ msg : 'forbidden Request' });
      }
      if (role === "farmer") {
        return res.status(404).json({ msg : 'forbidden Request' });
      }
      const checkRole = await users.checkUserRole(role);
      if (!checkRole || !checkRole.length){
      await users.createUserRole({role : role});
      }
      await users.createPermission({wallet_id: wallet_id, role_id: role_id});
      const token =  await users.genToken(input);
      await users.createUserToken(token);
      //const user_name = await users.fetchUserName(wallet_id);
      /** try {
        await sendEmail(email, WelcomeMail(name));
      } catch (error) {
        console.log(error);
      } **/
      return res.json({token , msg : 'admin user registered'});
      
    } catch (error) {
        console.error(error.message);
        return res.status(500).json({ msg: 'Internal server error create admin user' });
    }
  };


  exports.updateUserPermission = async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
  
    const { wallet_id, user_role, role_id } = req.body;
    try {
      const userExists = await users.checkUserExists(wallet_id);
      if (!userExists && !userExists.length) {
        return res.status(403).json({ msg : 'userNotExists' });
      }
      if (user_role === "admin" || role_id == 1){
        return res.status(404).json({ msg : 'forbidden Request' });
      }
     /** if (wallet_id !== req.user.wallet_id) {
        return res.status(403).json({ msg : 'user wallet id mismatch' });
      } **/
      
      /** const checkRole = await users.checkUserRole(user_role);
      if (!checkRole || !checkRole.length){
      await users.createUserRole({role : user_role});
      } **/

      let input = {
        role_id : role_id,
        wallet_id : wallet_id
      }

      await users.updatePermission(input);
      //const user_name = await users.fetchUserName(wallet_id);
      /** try {
        await sendEmail(email, WelcomeMail(name));
      } catch (error) {
        console.log(error);
      } **/
      return res.json({input , msg : ' user permission updated'});
      
    } catch (error) {
        console.error(error.message);
        return res.status(500).json({ msg: 'Internal server error update user permission' });
    }
  };


  exports.getUserPermission = async (req, res) => {
    try {
      const wallet_id  = req.user.wallet_id;
      console.log(wallet_id);
      const user = await users.getUserPermission(wallet_id);
      return res.status(200).json(user);
    } catch (err) {
      console.error(err.message);
      return res.status(500).send('Internal server error get user permission');
    }
  };

  exports.getUserPermissions = async (req, res) => {
    try {
      const user = await users.getUserPermissions();
      return res.status(200).json(user);
    } catch (err) {
      console.error(err.message);
      return res.status(500).send('Internal server error get user permissions');
    }
  };

  exports.getUserRoles = async (req, res) => {
    try {
      const user = await users.getUserRoles();
      return res.status(200).json(user);
    } catch (err) {
      console.error(err.message);
      return res.status(500).send('Internal server error get user roles');
    }
  };

  exports.getBuyers = async (req, res) => {
    try {
      const buyers = await users.getBuyers();
      return res.status(200).json(buyers);
    } catch (err) {
      console.error(err.message);
      return res.status(500).send('Internal server error get buyers');
    }
  };

  exports.createUserRole = async (req, res) => {
    try {
      //const checkRole = await users.checkUserRole(req.body.role);
      if (checkRole || checkRole.length){
        return res.status(403).json({ msg : 'userRoleExists' });
        }
      const user = await users.createUserRole(req.body.role);
      return res.status(200).json(user);
    } catch (err) {
      console.error(err.message);
      return res.status(500).send('Internal server error create user roles');
    }
  };


  exports.updateUserRole = async (req, res) => {
    try {
      /** const checkRole = await users.checkUserRole(req.body.role);
      if (checkRole || checkRole.length){
        return res.status(403).json({ msg : 'userRoleExists' });
        } **/
      const user = await users.updateUserRole(req.body);
      return res.status(200).json(user);
    } catch (err) {
      console.error(err.message);
      return res.status(500).send('Internal server error update user roles');
    }
  };

  