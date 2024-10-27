

const db = require('../models/db');
const moment = require('moment');
const jwt = require('jsonwebtoken');
const userModel = require('../models/users');
const config = require('../config');


exports.getDetailsByWalletId = async (data) => {
  const query = db.read.select('axk_users.*')
    .from('axk_users')
    .where('wallet_id', '=', data);
  return query;
};

exports.getUserDetailsByEmail = async (email) => {
  const query = db.read.select('*')
    .from('axk_users')
    .where('email', '=', email);
  return query;
};


exports.checkUserExists = async (data) => {
  const query = db.read.select('axk_users.*')
    .from('axk_users')
    .where('email', '=', data)
    .orWhere('wallet_id', '=', data);
  return query;
};

exports.getUserEmailByWalletId = async (data) => {
  const query = db.read.select('axk_users.email')
    .from('axk_users')
    .where('wallet_id', '=', data);
  //.orWhere('wallet_id', '=', data);
  return query;
};



exports.getUserDetailsByNameOrEmail = async (input) => {
  const query = db.read.select('*')
    .from('axk_users')
    .where('name', '=', input)
    .orWhere('email', '=', input);
  return query;
};

exports.createUser = async (data) => {
  const createdAt = moment().format('YYYY-MM-DD HH:mm:ss');
  const query = db.write('axk_users').insert({
    name: data.name || null,
    email: data.email || null,
    password: data.password || null,
    pin: data.pin || null,
    wallet_id: data.wallet_id || null,
    kyc: data.kyc || 0,
    verified_email: data.verified_email || 0,
    latitude: data.latitude || null,
    longitude: data.longitude || null,
    flag: 0,
    created_at: createdAt,
    updated_at: createdAt
  });
  console.info("query -->", query.toQuery())
  return query;
};

exports.deleteUser = async (email) => {
  console.log("del to axk users", email)
  const query = db.write('axk_users')
    .from('axk_users')
    .where('email', '=', email)
    .del()
  return query;
};



exports.updatePassword = async (data) => {
  const query = db.write('axk_users')
    .where('email', data.email)
    .update({
      password: data.password,
      updated_at: moment().format('YYYY-MM-DD HH:mm:ss')
    });
  console.info("query -->", query.toQuery())
  return query;
};

exports.changePassword = async (data) => {
  const query = db.write('axk_users')
    .where('wallet_id', data.wallet_id)
    .update({
      password: data.password,
      updated_at: moment().format('YYYY-MM-DD HH:mm:ss')
    });
  console.info("query -->", query.toQuery())
  return query;
};

exports.resetPassword = async (data) => {
  const query = db.write('axk_users')
    .where('email', data.email)
    .update({
      password: data.token,
      updated_at: moment().format('YYYY-MM-DD HH:mm:ss')
    });
  console.info("query -->", query.toQuery())
  return query;
};

exports.setPassword = async (data) => {
  const query = db.write('axk_users')
    .where('email', data.email)
    .where('password', data.token)
    .update({
      password: data.password,
      updated_at: moment().format('YYYY-MM-DD HH:mm:ss')
    });
  console.info("query -->", query.toQuery())
  return query;
};

exports.fetchUserName = async (wallet_id) => {
  const query = db.read.select('axk_users.name')
    .from('axk_users')
    .where('wallet_id', '=', wallet_id)
    .orWhere('email', '=', wallet_id);
  return query;
};

exports.fetchUserPassword = async (wallet_id) => {
  const query = db.read.select('axk_users.password')
    .from('axk_users')
    .where('wallet_id', '=', wallet_id)
    .orWhere('email', '=', wallet_id);
  return query;
};

exports.fetchUserPin = async (wallet_id) => {
  const query = db.read.select('axk_users.pin')
    .from('axk_users')
    .where('wallet_id', '=', wallet_id);
  return query;
};

exports.updateProfile = async (data) => {
  const query = db.write('axk_users')
    .where('wallet_id', data.wallet_id)
    .update({
      name: data.name,
      email: data.email,
      latitude: data.latitude || null,
      longitude: data.longitude || null,
      updated_at: moment().format('YYYY-MM-DD HH:mm:ss')
    });
  console.info("query -->", query.toQuery())
  return query;
};

exports.fetchUserProfile = async (wallet_id) => {
  const query = db.read.select('axk_users.name', 'axk_users.email', 'axk_users.wallet_id', 'axk_users.latitude', 'axk_users.longitude')
    .from('axk_users')
    .where('wallet_id', '=', wallet_id);
  return query;
};

exports.verifyEmail = async (data) => {
  const query = db.write('axk_users')
    .where('wallet_id', data.wallet_id)
    .update({
      verified_email: data.verified || 1,
      updated_at: moment().format('YYYY-MM-DD HH:mm:ss')
    });
  console.info("query -->", query.toQuery())
  return query;
};


exports.deActiveUser = async (wallet_id) => {
  const query = db.write('axk_users')
    .where('wallet_id', wallet_id)
    .update({
      flag: 0,
      updated_at: moment().format('YYYY-MM-DD HH:mm:ss')
    });
  console.info("query -->", query.toQuery())
  return query;
};

exports.activeUser = async (wallet_id) => {
  const query = db.write('axk_users')
    .where('wallet_id', wallet_id)
    .update({
      flag: 1,
      updated_at: moment().format('YYYY-MM-DD HH:mm:ss')
    });
  console.info("query -->", query.toQuery())
  return query;
};

exports.setUserPin = async (data) => {
  const query = db.write('axk_users')
    .where('wallet_id', data.wallet_id)
    .update({
      pin: data.pin,
      updated_at: moment().format('YYYY-MM-DD HH:mm:ss')
    });
  console.info("query -->", query.toQuery())
  return query;
};


exports.isWalletIdFlagged = async (wallet_id) => {
  const query = db.read.select('axk_users.flag')
    .from('axk_users')
    .where('wallet_id', '=', wallet_id);

  return query;
};


exports.getAllUsers = async () => {
  const query = db.read.select('axk_users.*')
    .from('axk_users')
  return query;
};

exports.getBuyers = async () => {
  const query = db.read.select('axk_users.*')
    .from('axk_users')
    .join('axk_user_permission', 'axk_user_permission.wallet_id', '=', 'axk_users.wallet_id')
    .where('axk_user_permission.role_id', '=', 3);
  return query;
};

exports.createPermission = async (data) => {
  const createdAt = moment().format('YYYY-MM-DD HH:mm:ss');
  const query = db.write('axk_user_permission').insert({
    wallet_id: data.wallet_id,
    role_id: data.role_id || 2,
    created_at: createdAt,
    updated_at: createdAt
  });
  console.info("query -->", query.toQuery())
  return query;
};

exports.createBuyer = async (data) => {
  const createdAt = moment().format('YYYY-MM-DD HH:mm:ss');
  const query = db.write('axk_user_permission').insert({
    wallet_id: data,
    role_id: 3,
    created_at: createdAt,
    updated_at: createdAt
  });
  console.info("query -->", query.toQuery())
  return query;
};

exports.updatePermission = async (data) => {
  const query = db.write('axk_user_permission')
    .where('wallet_id', data.wallet_id)
    .update({
      role_id: data.role_id,
      updated_at: moment().format('YYYY-MM-DD HH:mm:ss')
    });
  console.info("query -->", query.toQuery())
  return query;
};

exports.getUserPermission = async (wallet_id) => {
  const query = db.read.select('axk_user_role.role')
    .from('axk_user_role')
    .join('axk_user_permission', 'axk_user_permission.role_id', '=', 'axk_user_role.id')
    .where('axk_user_permission.wallet_id', '=', wallet_id);
  console.info("query -->", query.toQuery())
  return query;
};

exports.getUserPermissions = async () => {
  const query = db.read.select('axk_user_permission.*')
    .from('axk_user_permission');
  //.join('axk_user_role', 'axk_user_permission.role_id', '=', 'axk_user_role.id')
  //.where('wallet_id', '=', wallet_id);
  console.info("query -->", query.toQuery())
  return query;
};

exports.deleteFromUserPermission = async (id) => {
  console.log("del to user permission", id)
  const query = db.write('axk_user_permission')
    .from('axk_user_permission')
    .where('wallet_id', '=', id)
    .del()
  return query;
};

exports.createUserRole = async (data) => {
  const createdAt = moment().format('YYYY-MM-DD HH:mm:ss');
  const query = db.write('axk_user_role').insert({
    role: data.role,
    created_at: createdAt,
    updated_at: createdAt
  });
  console.info("query -->", query.toQuery())
  return query;
};

exports.checkUserRole = async (role) => {
  const query = db.read.select('axk_user_role.id')
    .from('axk_user_role')
    .where('role', '=', role);
  console.info("query -->", query.toQuery())
  return query;
};

exports.getUserRoles = async () => {
  const query = db.read.select('*')
    .from('axk_user_role');
  //.where('role', '=', role);
  console.info("query -->", query.toQuery())
  return query;
};

exports.updateUserRole = async (data) => {
  const query = db.write('axk_user_role')
    .where('id', data.role_id)
    .update({
      role: data.role,
      updated_at: moment().format('YYYY-MM-DD HH:mm:ss')
    });
  console.info("query -->", query.toQuery())
  return query;
};

exports.updateRoleTime = async (data) => {
  const query = db.write('axk_user_role')
    .where('id', data.role_id)
    .update({
      created_at: moment().format('YYYY-MM-DD HH:mm:ss'),
      updated_at: moment().format('YYYY-MM-DD HH:mm:ss')
    });
  console.info("query -->", query.toQuery())
  return query;
};

exports.deleteFromUserRole = async (id) => {
  console.log("del to user role", id)
  const query = db.write('axk_user_role')
    .from('axk_user_role')
    .where('id', '=', id)
    .del()
  return query;
};

exports.createUserProfilePicture = async (data) => {
  const createdAt = moment().format('YYYY-MM-DD HH:mm:ss');
  const query = db.write('axk_user_images').insert({
    user_id: data.wallet_id,
    path: data.path,
    name: data.name,
    created_at: createdAt,
    updated_at: createdAt
  });
  console.info("query -->", query.toQuery())
  return query;
};

exports.updateUserProfilePicture = async (data) => {
  const query = db.write('axk_user_images')
    .where('user_id', data.wallet_id)
    .update({
      path: data.path,
      name: data.name,
      updated_at: moment().format('YYYY-MM-DD HH:mm:ss')
    });
  console.info("query -->", query.toQuery())
  return query;
};

exports.getUserProfilePicture = async (wallet_id) => {
  const query = db.read.select('axk_user_images.*')
    .from('axk_user_images')
    .where('user_id', '=', wallet_id);
  console.info("query -->", query.toQuery())
  return query;
};
/** exports.getUserPermission = async (wallet_id) => {
  const query = db.read.select('axk_user_role.role')
  .from('axk_user_permission')
  .join('axk_user_role', 'axk_user_permission.role_id', '=', 'axk_user_role.id')
  .where('wallet_id', '=', wallet_id)
  console.info("query -->", query.toQuery())
  return query;
}; **/

exports.createUserToken = async (data) => {
  const createdAt = moment().format('YYYY-MM-DD HH:mm:ss');
  const query = db.write('axk_auth_jwt').insert({
    wallet_id: data.wallet_id,
    token: data.token,
    expiration: data.expiration,
    created_at: createdAt,
    updated_at: createdAt
  });
  console.info("query -->", query.toQuery())
  return query;
};

exports.updateUserToken = async (data) => {
  const query = db.write('axk_auth_jwt')
    .where('wallet_id', data.wallet_id)
    .update({
      token: data.token,
      expiration: data.expiration,
      updated_at: moment().format('YYYY-MM-DD HH:mm:ss')
    });
  console.info("query -->", query.toQuery())
  return query;
};

exports.updateCurrentUserToken = async (data) => {
  const query = db.write('axk_auth_jwt')
    .where('token', data.token)
    .update({
      token: data.new_token,
      expiration: data.expiration,
      updated_at: moment().format('YYYY-MM-DD HH:mm:ss')
    });
  console.info("query -->", query.toQuery())
  return query;
};

exports.getUserTokenByWalletId = async (wallet_id) => {
  const query = db.read.select('axk_auth_jwt.wallet_id', 'axk_auth_jwt.token', 'axk_auth_jwt.expiration')
    .from('axk_auth_jwt')
    .where('wallet_id', '=', wallet_id)
  console.info("query -->", query.toQuery())
  return query;
};

exports.getUserTokenById = async (token) => {
  const query = db.read.select('axk_auth_jwt.wallet_id', 'axk_auth_jwt.token', 'axk_auth_jwt.expiration')
    .from('axk_auth_jwt')
    .where('token', '=', token);
  console.info("query -->", query.toQuery())
  return query;
};

exports.getCurrentTokenUser = async (data) => {
  const query = db.read.select('axk_auth_jwt.wallet_id', 'axk_auth_jwt.token', 'axk_auth_jwt.expiration')
    .from('axk_auth_jwt')
    .where('wallet_id', '=', data)
    .orWhere('token', '=', data);
  console.info("query -->", query.toQuery())
  return query;
};

exports.deleteUserToken = async (wallet_id) => {
  console.log("del to axk auth jwt", wallet_id)
  const query = db.write('axk_auth_jwt')
    .from('axk_auth_jwt')
    .where('wallet_id', '=', wallet_id)
    .del()
  return query;
};

exports.getActiveEmailToken = async (email) => {
  const query = db.read.select('axk_email_token.email', 'axk_email_token.token', 'axk_email_token.expiry')
    .from('axk_email_token')
    .where('email', '=', email)
    .where('used', '=', 0);
  console.info("query -->", query.toQuery())
  return query;
};

exports.getUsedEmailToken = async (email) => {
  const query = db.read.select('axk_email_token.email', 'axk_email_token.token', 'axk_email_token.expiry')
    .from('axk_email_token')
    .where('email', '=', email)
    .where('used', '=', 1);
  console.info("query -->", query.toQuery())
  return query;
};

exports.getOtpToken = async (token) => {
  const query = db.read.select('axk_email_token.email', 'axk_email_token.token', 'axk_email_token.expiry')
    .from('axk_email_token')
    .where('token', '=', token)
    .where('used', '=', 0);
  console.info("query -->", query.toQuery())
  return query;
};

exports.createEmailToken = async (data) => {
  const createdAt = moment().format('YYYY-MM-DD HH:mm:ss');
  const query = db.write('axk_email_token').insert({
    email: data.email,
    token: data.token,
    expiry: data.expiry,
    used: 0,
    created_at: createdAt,
    updated_at: createdAt
  });
  console.info("query -->", query.toQuery())
  return query;
};

exports.verifyEmailTokenDb = async (data) => {
  const query = db.write('axk_email_token')
    .update({
      used: 1,
      updated_at: moment().format('YYYY-MM-DD HH:mm:ss')
    })
    .where('email', '=', data.email)
    .where('token', '=', data.token)
    .where('used', '=', 0);
  console.info("query -->", query.toQuery())
  return query;
};



exports.genAuthToken = function (user, pass, role) {
  try {
    var tk = {};
    jwt.sign({
      data: {
        wallet_id: user,
        user: pass,
        role: role
      }
    }, config.JWT_SECRET, { expiresIn: '48h' }, (err, decoded) => {
      if (err) {
        tk.error = err.message;
        return tk;
      }
      else {
        tk.token = decoded;
        //console.log(tk)

      }
    })
    return tk;
  }
  catch (err) {
    tk.error = err.message;
    return err.message;
  }
}

exports.genAdminToken = function (user, pass, role) {
  try {
    var tk = {};
    jwt.sign({
      data: {
        wallet_id: user,
        user: pass,
        role: role
      }
    }, config.ADM_SECRET, { expiresIn: config.JWT_ADM_EXPIRES_IN }, (err, decoded) => {
      if (err) {
        tk.error = err.message;
        return tk;
      }
      else {
        tk.token = decoded;
        //console.log(tk)

      }
    })
    return tk;
  }
  catch (err) {
    tk.error = err.message;
    return err.message;
  }
}


exports.genEmailToken = function (user, pass) {
  try {
    var tk = {};
    jwt.sign({
      data: {
        email: user,
        wallet_id: pass
      }
    }, config.JWT_SECRET, { expiresIn: config.JWT_TOKEN_EXPIRES_IN }, (err, decoded) => {
      if (err) {
        tk.error = err.message;
        return tk;
      }
      else {
        tk.token = decoded;
        //console.log(tk)

      }
    })
    return tk;
  }
  catch (err) {
    tk.error = err.message;
    return err.message;
  }
}

function getExpDate(tkn) {
  try {
    var tokenVer = {};
    jwt.verify(tkn, config.JWT_SECRET, (err, decoded) => {
      if (err) throw err;
      else {
        tokenVer.data = decoded;
        //console.log(tokenVer)
      }
    })
    return tokenVer;
    //console.log(tokenVer);
  }
  catch (err) {
    tokenVer.error = err.message;
    return tokenVer;
  }
}

function getExpDateAdm(tkn) {
  try {
    var tokenVer = {};
    jwt.verify(tkn, config.ADM_SECRET, (err, decoded) => {
      if (err) throw err;
      else {
        tokenVer.data = decoded;
        //console.log(tokenVer)
      }
    })
    return tokenVer;
    //console.log(tokenVer);
  }
  catch (err) {
    tokenVer.error = err.message;
    return tokenVer;
  }
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

exports.genToken = async (reqData) => {
  const userExists = await userModel.getDetailsByWalletId(reqData);
  console.log(userExists);
  var token = {};
  if (userExists && userExists.length) {
    const role = await this.getUserPermission(userExists[0].wallet_id);
    var tkn = await userModel.genAuthToken(userExists[0].wallet_id, userExists[0].name, role[0].role);
    await sleep(1000);
    if (tkn) {
      var tkExp = getExpDate(tkn.token);
      await sleep(1000);
      //console.log(tkExp);
      token.wallet_id = userExists[0].wallet_id;
      token.expiration = tkExp.data.exp;
      token.token = tkn.token;
      //console.log(token);
    }
    // }
    return token;
  }

}

exports.updateToken = async (reqData) => {
  const userExists = await userModel.getDetailsByWalletId(reqData);
  if (userExists && userExists.length) {
    var token = {};
    var input = {};
    input.wallet_id = userExists[0].wallet_id;
    var currentToken = await userModel.getUserTokenByWalletId(userExists[0].wallet_id);
    var timeNow = Math.floor(Date.now() / 1000);
    var db_role = await this.getUserPermission(userExists[0].wallet_id);
    if (currentToken && currentToken.length && db_role && db_role.length) {
      console.log(currentToken + " : " + db_role[0].role);
      let _expiry = currentToken[0].expiration;
      let _token = currentToken[0].token;
      let checkId = await userModel.verifyToken(_token);
      let _checkId = checkId.wallet_id;
      let _id = userExists[0].wallet_id;
      let _role = checkId.role;
      let role = db_role[0].role;
      if (_expiry <= timeNow & role != "admin" || role != "admin" && _checkId !== _id) {
        var newToken = await userModel.genAuthToken(userExists[0].wallet_id, userExists[0].name, role);
        await sleep(1000);
        if (newToken) {
          var tkExp = await getExpDate(newToken.token);
          await sleep(1000);
          token.wallet_id = userExists[0].wallet_id;
          token.expiration = tkExp.data.exp;
          token.token = newToken.token;
          input.wallet_id = userExists[0].wallet_id;
          input.token = newToken.token;
          input.expiration = tkExp.data.exp;
          const response = await userModel.updateUserToken(input);
          if (response && response.length) {
            token.message = 'updated';
          }
        }
        return token;
      } else if (_expiry > timeNow && role != "admin") {
        token.wallet_id = userExists[0].wallet_id;
        token.message = 'valid';
        token.expiration = currentToken[0].expiration;
        token.token = currentToken[0].token;
        //console.log(token);
        return token;
      } else if (_expiry <= timeNow && role == "admin" || role == "admin" && _checkId !== _id) {
        var newToken = await userModel.genAdminToken(userExists[0].wallet_id, userExists[0].name, role);
        await sleep(1000);
        if (newToken) {
          var tkExp = getExpDateAdm(newToken.token);
          await sleep(1000);
          token.wallet_id = userExists[0].wallet_id;
          token.expiration = tkExp.data.exp;
          token.token = newToken.token;
          input.wallet_id = userExists[0].wallet_id;
          input.token = newToken.token;
          input.expiration = tkExp.data.exp;
          const response = await userModel.updateUserToken(input);
          if (response && response.length) {
            token.message = 'updated';
          }
        }
        return token;
      } else if (_expiry > timeNow && role == "admin") {
        const curr_token = await userModel.verifyAdminToken(_token);
        console.log(curr_token);
        if (!curr_token || curr_token.error || curr_token.message == "error" || curr_token.role == "error") {
          var new_token = await userModel.genAdminToken(userExists[0].wallet_id, userExists[0].name, role);
          await sleep(1000);
          if (new_token) {
            var tkExp = getExpDateAdm(new_token.token);
            await sleep(1000);
            token.wallet_id = userExists[0].wallet_id;
            token.expiration = tkExp.data.exp;
            token.token = new_token.token;
            input.wallet_id = userExists[0].wallet_id;
            input.token = new_token.token;
            input.expiration = tkExp.data.exp;
            const response = await userModel.updateUserToken(input);
            if (response && response.length) {
              token.message = 'updated';
            }
          }
          return token;
        }
        else {
          token.wallet_id = userExists[0].wallet_id;
          token.message = 'valid';
          token.expiration = currentToken[0].expiration;
          token.token = currentToken[0].token;
          //console.log(token);
          return token;
        }
      }
    } else { //(!currentToken && !currentToken.length)
      var usr_role = await this.getUserPermission(userExists[0].wallet_id);
      let initToken, tkInitExp, curr_role = usr_role[0].role;
      if (curr_role == "admin") {
        initToken = await userModel.genAdminToken(userExists[0].wallet_id, userExists[0].name, curr_role);
        await sleep(1000);
        tkInitExp = getExpDateAdm(initToken.token);
        await sleep(1000);
      } else {
        initToken = await userModel.genAuthToken(userExists[0].wallet_id, userExists[0].name, curr_role);
        await sleep(1000);
        tkInitExp = getExpDate(initToken.token);
        await sleep(1000);

      }

      if (initToken && tkInitExp) {
        //console.log(tkExp);
        token.wallet_id = userExists[0].wallet_id;
        token.expiration = tkInitExp.data.exp;
        token.token = initToken.token;
        //token.message = 'updated';
        input.wallet_id = userExists[0].wallet_id;
        input.token = initToken.token;
        input.expiration = tkInitExp.data.exp;
        const response = await userModel.createUserToken(input);
        if (response && response.length) {
          token.message = 'created';
        }
        return token;
      }
    }
  }
}

exports.genVerToken = async (reqData) => {
  //const validInput = validateDetails.validateEmailAuth(reqData);
  const userExists = await userModel.getUserDetailsByEmail(reqData);
  var token = {};
  if (userExists && userExists.length) {
    var tkn = await userModel.genEmailToken(userExists[0].email, userExists[0].wallet_id);
    await sleep(1000);
    if (tkn) {
      var tkExp = getExpDate(tkn.token);
      await sleep(1000);
      //console.log(tkExp);
      token.wallet_id = userExists[0].wallet_id;
      token.email = userExists[0].email;
      token.expiry = tkExp.data.exp;
      token.token = tkn.token;
      token.user = userExists[0].name;
      //console.log(token);
    }
    // }
    return token;
  }
}

exports.verifyToken = async (token) => {
  try {
    var valid = false;
    var resp = {};
    jwt.verify(token, config.JWT_SECRET, (err, decoded) => {
      if (err) {
        resp.token = token;
        resp.expiry = 0;
        resp.valid = valid;
        resp.wallet_id = token;
        resp.user = token;
        resp.role = "error";
        resp.message = "error";
        return resp;
      }
      else {
        //tokenVer.
        var data = decoded;
        console.log(data);
        var expiration = data.exp;//getExpDate(token);
        //await sleep(1000);
        let _walletid = data.data.wallet_id;
        let _user = data.data.user;
        let _role = data.data.role;
        var timeNow = Math.floor(Date.now() / 1000);
        if (expiration <= timeNow) {
          valid = true;
          resp.token = token;
          resp.expiry = expiration;
          resp.valid = valid;
          resp.wallet_id = _walletid;
          resp.user = _user;
          resp.role = _role;
          resp.message = "expired";
        }
        else {
          valid = true;
          resp.token = token;
          resp.expiry = expiration;
          resp.valid = valid;
          resp.wallet_id = _walletid;
          resp.user = _user;
          resp.role = _role;
          resp.message = "valid";
        }

      }
    })
    return resp;
    //console.log(tokenVer);
  }
  catch (err) {
    resp.token = token;
    resp.expiry = 0;
    resp.valid = valid;
    resp.wallet_id = token;
    resp.user = token;
    resp.role = "error"
    resp.message = "error";
    return resp;
  }
}

exports.verifyAdminToken = async (token) => {
  try {
    var valid = false;
    var resp = {};
    jwt.verify(token, config.ADM_SECRET, (err, decoded) => {
      if (err) {
        resp.token = token;
        resp.expiry = 0;
        resp.valid = valid;
        resp.wallet_id = token;
        resp.user = token;
        resp.role = "error";
        resp.message = "error";
        return resp;
      }
      else {
        //tokenVer.
        var data = decoded;
        console.log(data);
        var expiration = data.exp;//getExpDate(token);
        //await sleep(1000);
        let _walletid = data.data.wallet_id;
        let _user = data.data.user;
        let _role = data.data.role;
        var timeNow = Math.floor(Date.now() / 1000);
        if (expiration <= timeNow) {
          valid = true;
          resp.token = token;
          resp.expiry = expiration;
          resp.valid = valid;
          resp.wallet_id = _walletid;
          resp.user = _user;
          resp.role = _role;
          resp.message = "expired";
        }
        else {
          valid = true;
          resp.token = token;
          resp.expiry = expiration;
          resp.valid = valid;
          resp.wallet_id = _walletid;
          resp.user = _user;
          resp.role = _role;
          resp.message = "valid";
        }

      }
    })
    return resp;
    //console.log(tokenVer);
  }
  catch (err) {
    resp.token = token;
    resp.expiry = 0;
    resp.valid = valid;
    resp.wallet_id = token;
    resp.user = token;
    resp.role = "error"
    resp.message = "error";
    return resp;
  }
}

exports.verifyEmailToken = async (token) => {
  try {
    var valid = false;
    var resp = {};
    jwt.verify(token, config.JWT_SECRET, (err, decoded) => {
      if (err) {
        resp.token = token;
        resp.expiry = 0;
        resp.valid = valid;
        resp.email = token;
        resp.wallet_id = token;
        resp.message = "error";
        return resp;
      }
      else {
        //tokenVer.
        var data = decoded;
        console.log(data);
        var expiration = data.exp;//getExpDate(token);
        //await sleep(1000);
        let _email = data.data.email;
        let _wallet_id = data.data.wallet_id;
        var timeNow = Math.floor(Date.now() / 1000);
        if (expiration <= timeNow) {
          valid = true;
          resp.token = token;
          resp.expiry = expiration;
          resp.valid = valid;
          resp.email = _email;
          resp.wallet_id = _wallet_id;
          resp.message = "expired";
        }
        else {
          valid = true;
          resp.token = token;
          resp.expiry = expiration;
          resp.valid = valid;
          resp.email = _email;
          resp.wallet_id = _wallet_id;
          resp.message = "valid";
        }

      }
    })
    return resp;
    //console.log(tokenVer);
  }
  catch (err) {
    resp.token = token;
    resp.expiry = 0;
    resp.valid = valid;
    resp.email = token;
    resp.wallet_id = token;
    resp.message = "error";
    return resp;
  }
}


