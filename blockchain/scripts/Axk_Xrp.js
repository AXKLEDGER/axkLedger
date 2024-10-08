const { Client, Wallet, xrpToDrops, dropsToXrp } = require('xrpl');
const express = require('express');
const moment = require('moment');
const CryptoJS = require("crypto-js");
const pinHash = require('sha256');
const bcrypt = require('bcryptjs');
const saltRounds = 10;

const router  = express.Router();
const {successResponse, errorResponse} = require('../xrp/libs/response');
   const logStruct = (func, error) => {
    return {'func': func, 'file': 'Axk_Xrp', error}
  }


  const generateXrpWalletTestNet = async() => {
    try
    { 
          // Define the network client
        const client = new Client("wss://s.altnet.rippletest.net:51233")
        await client.connect()

        const wallet = Wallet.generate()
        const fund_result = await client.fundWallet(wallet);
        const test_wallet = fund_result.wallet
        let _wallet =
            {
              "wallet" : wallet,
              "fund_result" : fund_result,
              "test_wallet" : test_wallet
            }
        return successResponse(200, _wallet, {"wallet" : _wallet}, "wallet created");

        // Disconnect when done (If you omit this, Node.js won't end the process)
        await client.disconnect()
     }catch (error) {
            console.error('error -> ', logStruct('generateXrpWalletTestNet', error))
            return errorResponse(error.status, error.message);
          }
  }

  router.get('/test/generate', async(req, res, next) => {
    const response = await generateXrpWalletTestNet();
    return res.status(response.status).send(response)
  });

  const createFundXrpWalletTestNet = async(data) => {
    try
    { 
        let comb = data.passpharse + data.username;
        const matchPwd = bcrypt.compareSync(String(comb), data.encrypted);
           //validTx.passphrase == cryptPwd ? true : false;
           if (!matchPwd) {
             return errorResponse(401,"passphrase_wrong", {message : "wrongPassphrase"});
           }
    
        let kystr = CryptoJS.AES.decrypt(data.mnemonic, pinHash(comb));
        const _mnemonic = kystr.toString(CryptoJS.enc.Utf8);
          // Define the network client
        const client = new Client("wss://s.altnet.rippletest.net:51233")
        await client.connect()
        const _wallet = Wallet.fromMnemonic(_mnemonic);
        const fund_result = await client.fundWallet(_wallet);
        const test_wallet = fund_result.wallet
        console.log(fund_result)
        let wallet =
            {
              "wallet" : test_wallet,
              "result" : fund_result
            }
        return successResponse(200, wallet, {"wallet" : wallet}, "wallet created and funded");

        // Disconnect when done (If you omit this, Node.js won't end the process)
        await client.disconnect()
     }catch (error) {
            console.error('error -> ', logStruct('createFundXrpWalletTestNet', error))
            return errorResponse(error.status, error.message);
          }
  }

  router.post('/test/fund', async(req, res, next) => {
    const response = await createFundXrpWalletTestNet(req.body);
    return res.status(response.status).send(response)
  });

  const getXrpWalletTestNetAccountInfo = async(data) => {
    try
    { 
        let comb = data.passpharse + data.username;
        const matchPwd = bcrypt.compareSync(String(comb), data.encrypted);
           //validTx.passphrase == cryptPwd ? true : false;
           if (!matchPwd) {
             return errorResponse(401,"passphrase_wrong", {message : "wrongPassphrase"});
           }
    
        let kystr = CryptoJS.AES.decrypt(data.mnemonic, pinHash(comb));
        const _mnemonic = kystr.toString(CryptoJS.enc.Utf8);
          // Define the network client
        
        const client = new Client("wss://s.altnet.rippletest.net:51233")
        await client.connect()
        const wallet = Wallet.fromMnemonic(_mnemonic);
          // Get info from the ledger about the address we just funded
        const response = await client.request({
            "command": "account_info",
            "account": wallet.address,
            "ledger_index": "validated"
        })
        console.log(response)
        let _response =
            {
              "wallet" : wallet.address,
              "details" : response
            }
        return successResponse(200, _response, {"info" : _response}, "wallet account info");

        // Disconnect when done (If you omit this, Node.js won't end the process)
        await client.disconnect()
     }catch (error) {
            console.error('error -> ', logStruct('getXrpWalletTestNetAccountInfo', error))
            return errorResponse(error.status, error.message);
          }
  }

  router.post('/test/account', async(req, res, next) => {
    const response = await getXrpWalletTestNetAccountInfo(req.body);
    return res.status(response.status).send(response)
  });

  const createPaymentXrpTestnet = async(data) => {
    try
    { 
        let comb = data.passpharse + data.username;
        const matchPwd = bcrypt.compareSync(String(comb), data.encrypted);
           //validTx.passphrase == cryptPwd ? true : false;
           if (!matchPwd) {
             return errorResponse(401,"passphrase_wrong", {message : "wrongPassphrase"});
           }
    
        let kystr = CryptoJS.AES.decrypt(data.mnemonic, pinHash(comb));
        const _mnemonic = kystr.toString(CryptoJS.enc.Utf8);
          // Define the network client
        
        const client = new Client("wss://s.altnet.rippletest.net:51233")
        await client.connect()
        const wallet = Wallet.fromMnemonic(_mnemonic);
          // Get info from the ledger about the address we just funded
      

        const tx = {
          TransactionType: "Payment",
          Account: wallet.address,
          Amount: xrpToDrops(data.amount),
          Destination: process.env.XRP_ESCROW_ACCOUNT
        };
      
          // Submit the transaction --------------------------------------------
          console.log("Submitting the transaction (Takes 3-5 seconds)");
          const submitted_tx = await client.submitAndWait(tx, {
            autofill: true, // Adds in fields that can be automatically set like fee and last_ledger_sequence
            wallet: wallet
          });
        // Check transaction results -----------------------------------------
        console.log(
          "Transaction result:",
          submitted_tx.result.meta.TransactionResult
        );
        // Look up the new account balances by sending a request to the ledger
          const account_info = await client.request({
            command: "account_info",
            account: wallet.address
          });

          // See https://xrpl.org/account_info.html#account_info ---------------
          const balance = account_info.result.account_data.Balance;
          console.log(`New account balance: ${balance} drops`);
          console.log("Numeric Balance :" + dropsToXrp(balance))
              
              let _response =
                  {
                    "txResult" : submitted_tx.result.meta.TransactionResult,
                    "details" : submitted_tx,
                    "amount" : xrpToDrops(data.amount),
                    "destination" : process.env.XRP_ESCROW_ACCOUNT
                  }
              return successResponse(200, _response, {"info" : _response}, "xrp payment transaction info");

              // Disconnect when done (If you omit this, Node.js won't end the process)
              await client.disconnect()
    }catch (error) {
        console.error('error -> ', logStruct('createPaymentXrpTestnet', error))
        return errorResponse(error.status, error.message);
    }
  }

  router.post('/test/payment', async(req, res, next) => {
    const response = await createPaymentXrpTestnet(req.body);
    return res.status(response.status).send(response)
  });



  module.exports = router;

