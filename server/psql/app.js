const express = require('express');
const cors = require('cors'); 
const logger = require('./middleware/logger');
const cookieParser = require('cookie-parser');

 const app = express();

  app.use(express.json());
  app.use(cors());

  app.use(express.urlencoded({extended: true})); 
  app.use(express.json());

  app.use(function(req, res, next) {
      res.header('Access-Control-Allow-Origin', '*');
      res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept');
      next();
  });
  /* Cookie Parser */
  app.use(cookieParser());
  app.use(logger)


module.exports = app;