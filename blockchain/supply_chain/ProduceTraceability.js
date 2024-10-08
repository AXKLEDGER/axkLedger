// Set up web3 with Lisk provider
const {Web3, HttpProvider} = require("web3");
const link_testnet_rpc = 'https://rpc.sepolia-api.lisk.com';
const {BigNumber} = require("bignumber.js");
//const provider = new Theta.providers.HttpProvider('https://eth-rpc-api-testnet.thetatoken.org/rpc');
const web3 = new Web3(link_testnet_rpc);
const chainId = 4202
const BN = require('bn.js');
const contracts = require("../abi/contracts");
const moment = require("moment");
require('dotenv').config({ path: '../../.env'});

const {abi} = require("../abi/ProduceTraceability.json");

const contractAddress = contracts.ProduceTraceability;

const ProduceTraceabilityContract = new web3.eth.Contract(abi, contractAddress);

const privateKey = process.env.LISK_PRIV_KEY;
const fromAddress = process.env.SUPPLY_CHAIN_ADDRESS;

async function sendTransaction(tx, fromAddress, privateKey) {
    try {
        const gas = await tx.estimateGas({ from: fromAddress });
        console.log("gas :" + gas);
        const gasPrice = await web3.eth.getGasPrice();
        const count = await web3.eth.getTransactionCount(fromAddress);
        const txData = tx.encodeABI();
        const nonce = web3.utils.toHex(count);
        
        const signedTx = await web3.eth.accounts.signTransaction(
            {
                to: contractAddress,
                data: txData,
                nonce: nonce,
                gas,
                gasPrice,
            },
            privateKey
        );

        const receipt = await web3.eth.sendSignedTransaction(signedTx.rawTransaction);
        console.log('Transaction receipt: ', receipt);
        return receipt;
    } catch (error) {
        console.error('Transaction error: ', error);
    }
}




// Function to register a farmer  
async function registerFarmer(data) { 
    const tx = ProduceTraceabilityContract.methods.registerFarmer({ name : data.name, location : data.location, address : data.address});
    const register_response = await sendTransaction(tx, fromAddress, privateKey);
    let dataReg = {
      txHash : register_response.transactionHash,
      name : data.name,
      location : data.location,
      address : data.address
    };
    return dataReg;
}

// Function to verify a  farmer  
async function verifyFarmer(data) { 
    const tx = ProduceTraceabilityContract.methods.verifyFarmer(data);
    const verify_response = await sendTransaction(tx, fromAddress, privateKey);
    let dataVer = {
      txHash : verify_response.transactionHash,
      farmer : data
    };
    return dataVer;
}

// Function to add  farmer produce  
async function addFarmProduce(data) { 
    //data.index = Math.floor(Math.random() * 9000000000) + 1000000000;
    data.storage = moment().format('YYYY-MM-DD HH:mm:ss');
    console.log(data);
    const tx = ProduceTraceabilityContract.methods.addFarmProduce(data.produce, data.producer, data.quality, data.storage, data.farmer, data.agents);
    const add_response = await sendTransaction(tx, fromAddress, privateKey);
    let dataAdd = {
      txHash : add_response.transactionHash,
      produce : data.produce,
      producer : data.producer,
      quality : data.quality,
      storage : data.storage,
      farmer : data.farmer,
      agents : data.agents
    };
    return dataAdd;
}

// Function to add  farmer produce  sale
async function sellFarmProduce(data) { 
    data.index = Math.floor(Math.random() * 9000000000) + 1000000000;
    const tx = ProduceTraceabilityContract.methods.sellFarmProduce(data.index, data.source, data.name, data.quantity, data.price, data.farmer);
    const sell_response = await sendTransaction(tx, fromAddress, privateKey);
    let dataSell = {
      txHash : sell_response.transactionHash,
      index : data.index,
      source : data.source,
      name : data.name,
      quantity : data.quantity,
      price : data.price,
      farmer : data.farmer
    };
    return dataSell;
}

// Function to get farmer details
async function getFarmer(data) {
    const farmer = await ProduceTraceabilityContract.methods.getFarmer(data).call();
    return farmer;
}

// Function to get farmer produce details
async function getProduce(data) {
    const produce = await ProduceTraceabilityContract.methods.getProduce(data).call();
    return produce;
}

// Function to get farmer produce index
async function getProduceIndex(data) {
    const index = await ProduceTraceabilityContract.methods.getProduceIndex(data).call();
    return index;
}

// Function to get farmer produce sale
async function getProduceSale(data) {
    const prod_sale = await ProduceTraceabilityContract.methods.getProduceSale(data).call();
    return prod_sale;
}

// Function to get farmer produce sale index
async function getProduceSaleIndex(data) {
    const sale = await ProduceTraceabilityContract.methods.getProduceSaleIndex(data).call();
    return sale;
}




module.exports = {
    registerFarmer,
    verifyFarmer,
    addFarmProduce,
    sellFarmProduce,
    getFarmer,
    getProduce,
    getProduceIndex,
    getProduceSale,
    getProduceSaleIndex
}