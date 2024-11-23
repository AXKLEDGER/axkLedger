'use strict';
const path = require('path');
const configureRoutes = require('./routes');
const config = require('./config');
const http = require('http');

const apiPort = config.API_PORT || '8000';
const blockchainPort = config.BLOCKCHAIN_PORT || '9000';

const app = require('./app');

configureRoutes(app);

// API Server setup
const apiServer = http.createServer(app);
apiServer.listen(apiPort, () => {
  console.log(`API Server running in ${config.NODE_ENV} mode on port ${apiPort}`);
});

apiServer.on('error', (error) => {
  console.error('API Server error:', error);
});

// Blockchain Server setup 
const blockchainServer = http.createServer(app);
blockchainServer.listen(blockchainPort, () => {
  console.log(`Blockchain Server running at port ${blockchainPort}`);
});

blockchainServer.on('error', (error) => {
  console.error('Blockchain Server error:', error);
});
