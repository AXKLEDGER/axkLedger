'use strict';

require('dotenv').config({ path: '../.env'});

//dotenv.config();

const http = require('http');
const port = process.env.SRV_PORT || '4055';

const app = require('./app');

app.set('port', port);

const server = http.createServer(app);

server.listen(port);

server.on('error', (error) => {
  console.error('error found', error);
});

server.on('listening', () => {
  console.log('Server running at :', port);
});
