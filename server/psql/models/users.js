

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
  const query = db.read.select('axk_users.id')
  .from('axk_users')
  .where('email', '=', data)
  .orWhere('wallet_id', '=', data);
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
    flag : 0,
    created_at: createdAt,
    updated_at: createdAt
  });
  console.info("query -->", query.toQuery())
  return query;
};

exports.updatePassword = async (data) => {
  const query = db.write('axk_users')
    .where('email', data.email)
    .update({
    password : data.password,
    updated_at : moment().format('YYYY-MM-DD HH:mm:ss')
  });
  console.info("query -->", query.toQuery())
  return query;
};

 exports.fetchUserName = async (wallet_id) => {
   const query = db.read.select('axk_users.name')
   .from('axk_users')
   .where('wallet_id', '=', wallet_id);
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
      name : data.name,
      email : data.email,
      latitude : data.latitude,
      longitude : data.logitude,
      updated_at: moment().format('YYYY-MM-DD HH:mm:ss')
    });
  console.info("query -->", query.toQuery())
  return query;
};

exports.verifyEmail = async (data) => {
  const query = db.write('axk_users')
    .where('wallet_id', data.wallet_id)
    .update({
    verified_email : data.verified || 1,
    updated_at : moment().format('YYYY-MM-DD HH:mm:ss')
  });
  console.info("query -->", query.toQuery())
  return query;
};


exports.deActiveUser = async (wallet_id) => {
  const query = db.write('axk_users')
    .where('wallet_id', wallet_id)
    .update({
    flag : 0,
    updated_at : moment().format('YYYY-MM-DD HH:mm:ss')
  });
  console.info("query -->", query.toQuery())
  return query;
};

exports.activeUser = async (wallet_id) => {
  const query = db.write('axk_users')
    .where('wallet_id', wallet_id)
    .update({
    flag : 1,
    updated_at : moment().format('YYYY-MM-DD HH:mm:ss')
  });
  console.info("query -->", query.toQuery())
  return query;
};

exports.setUserPin = async (data) => {
  const query = db.write('axk_users')
    .where('wallet_id', data.wallet_id)
    //.where('email', data.email)
    .update({
    pin : data.pin,
    updated_at : moment().format('YYYY-MM-DD HH:mm:ss')
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
    role_id: data.role_id || 3,
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
    role_id : data.role_id,
    updated_at : moment().format('YYYY-MM-DD HH:mm:ss')
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
      role : data.role,
      updated_at : moment().format('YYYY-MM-DD HH:mm:ss')
    });
  console.info("query -->", query.toQuery())
  return query;
};

exports.deleteFromUserRole = async (id) => {
  console.log("del to cart model", id)
  const query = db.write('axk_user_role')
  .from('axk_user_role')
  .where('id', '=', id)
  .del()
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
    wallet_id : data.wallet_id,
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
      token : data.token,
      expiration : data.expiration,
      updated_at : moment().format('YYYY-MM-DD HH:mm:ss')
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

exports.createEmailToken = async (data) => {
  const createdAt = moment().format('YYYY-MM-DD HH:mm:ss');
  const query = db.write('axk_email_token').insert({
    email : data.email,
    token : data.token,
    expiry : data.expiry,
    used: 0,
    created_at : createdAt,
    updated_at : createdAt
  });
  console.info("query -->", query.toQuery())
  return query;
};

exports.verifyEmailToken = async (data) => {
  const query = db.write('axk_email_token')
  .update({
     used : 1,
     updated_at : moment().format('YYYY-MM-DD HH:mm:ss')
   })
  .where('email', '=', data.wallet_id)
  .where('token', '=', data.token)
  .where('used', '=', 0);
  console.info("query -->", query.toQuery())
  return query;
};

 exports.genAuthToken = function (user, pass, role){
   try{
  var tk = {};
   jwt.sign({
     data: {
       wallet_id: user,
       user: pass,
       role : role
     }
   }, config.JWT_SECRET , { expiresIn: '48h' }, (err, decoded) =>{
     if(err) {
        tk.error = err.message;
        return tk;
     }
     else{
     tk.token = decoded;
     //console.log(tk)

   }
 })
return tk;
}
catch(err){
      tk.error = err.message;
      return  err.message;
}
}

exports.genEmailToken = function (user,pass){
  try{
 var tk = {};
  jwt.sign({
    data: {
      email: user,
      wallet_id: pass
    }
  }, config.JWT_SECRET , { expiresIn: config.JWT_TOKEN_EXPIRES_IN }, (err, decoded) =>{
    if(err) {
       tk.error = err.message;
       return tk;
    }
    else{
    tk.token = decoded;
    //console.log(tk)

  }
})
return tk;
}
catch(err){
     tk.error = err.message;
     return  err.message;
}
}

 function getExpDate(tkn){
  try{
   var tokenVer = {};
  jwt.verify(tkn, config.JWT_SECRET, (err, decoded) => {
    if (err) throw err;
    else{
    tokenVer.data = decoded;
    //console.log(tokenVer)
  }
})
return tokenVer;
//console.log(tokenVer);
}
catch(err){
    tokenVer.error = err.message;
     return tokenVer;
}
}
 function sleep(ms){
   return new Promise(resolve => setTimeout(resolve, ms));
 }

exports.genToken = async (reqData) => {
  //const validInput = validateDetails.validateAuth(reqData);
  const userExists = await userModel.getDetailsByWalletId(reqData.wallet_id);
  console.log(userExists);
  var token = {};
  if (userExists && userExists.length) {
    var tkn = await userModel.genAuthToken(userExists[0].wallet_id, userExists[0].name, reqData.role);
    await sleep(1000);
   if (tkn){
     var tkExp =  getExpDate(tkn.token);
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
  const userExists = await userModel.getDetailsByWalletId(reqData.wallet_id);
  if (userExists && userExists.length){
  var token = {};
  var input = {};
  input.wallet_id = userExists[0].wallet_id;
  var currentToken = await userModel.getUserTokenByWalletId(userExists[0].wallet_id);

  /** const getToken = await userModel.genAuthToken(userExists[0].email, userExists[0].password);
   await sleep(1000);
   //console.log(getToken)
  var tknExp = await getExpDate(getToken.token);
  await sleep(1000);
  //console.log(tknExp)  tknExp.data.exp  tknExp.data.exp  **/
  var timeNow = Math.floor(Date.now() / 1000);
 // console.log(timeNow)
  if (currentToken && currentToken.length){
   console.log(currentToken);
  let _expiry = currentToken[0].expiration;
  let _token = currentToken[0].token;
  let checkId = await userModel.verifyToken(_token);
  let _checkId = checkId.wallet_id;
  let _id = userExists[0].wallet_id;
  if(_expiry <= timeNow || _checkId !== _id){
    var newToken = await userModel.genAuthToken(userExists[0].wallet_id, userExists[0].name, reqData.role);
     await sleep(1000);
     if (newToken){
       var tkExp = await getExpDate(newToken.token);
       await sleep(1000);
       token.wallet_id = userExists[0].wallet_id;
       token.expiration = tkExp.data.exp;
       token.token = newToken.token;
       input.wallet_id = userExists[0].wallet_id;
       input.token = newToken.token;
       input.expiration = tkExp.data.exp;
       const response = await userModel.updateUserToken(input);
       if (response && response.length){
         token.message = 'updated';
       }
     }
     return token;
   }

   else  {
     token.wallet_id = userExists[0].wallet_id;
     token.message = 'valid';
     token.expiration = currentToken[0].expiration;
     token.token = currentToken[0].token;
      //console.log(token);
     return token;
   }
    }
 else { //(!currentToken && !currentToken.length)
    var initToken = await userModel.genAuthToken(userExists[0].wallet_id, userExists[0].name, reqData.role);
     await sleep(1000);
     if (initToken){
       var tkInitExp =  getExpDate(initToken.token);
       await sleep(1000);
       //console.log(tkExp);
       token.wallet_id = userExists[0].wallet_id;
       token.expiration = tkInitExp.data.exp;
       token.token = initToken.token;
       //token.message = 'updated';
       input.wallet_id = userExists[0].wallet_id;
       input.token = initToken.token;
       input.expiration = tkInitExp.data.exp;
       const response = await userModel.createUserToken(input);
       if (response && response.length){
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
   if (tkn){
     var tkExp =  getExpDate(tkn.token);
     await sleep(1000);
     //console.log(tkExp);
     token.wallet_id = userExists[0].wallet_id;
     token.email = userExists[0].email;
     token.expiration = tkExp.data.exp;
     token.token = tkn.token;
     token.user = userExists[0].name;
     //console.log(token);
   }
// }
return token;
}
}

exports.verifyToken = async (token) => {
  try{
   var valid = false;
   var resp = {};
  jwt.verify(token, config.JWT_SECRET, (err, decoded) => {
    if(err) {
       resp.token = token;
       resp.expiry = 0;
       resp.valid = valid;
       resp.wallet_id = token;
       resp.user = token;
       resp.message = "error";
       return resp;
    }
    else{
    //tokenVer.
    var data = decoded;
    console.log(data);
    var expiration = data.exp;//getExpDate(token);
    //await sleep(1000);
    let _walletid = data.data.wallet_id;
    let _user = data.data.user;
    var timeNow = Math.floor(Date.now() / 1000);
    if (expiration <= timeNow){
      valid = true;
      resp.token = token;
      resp.expiry = expiration;
      resp.valid = valid;
      resp.wallet_id = _walletid;
      resp.user = _user;
      resp.message = "expired";
    }
    else {
      valid = true;
      resp.token = token;
      resp.expiry = expiration;
      resp.valid = valid;
      resp.wallet_id = _walletid;
      resp.user = _user;
      resp.message = "valid";
    }

  }
})
return resp;
//console.log(tokenVer);
}
catch(err){
  resp.token = token;
  resp.expiry = 0;
  resp.valid = valid;
  resp.wallet_id = token;
  resp.user = token;
  resp.message = "error";
  return resp;
}
}