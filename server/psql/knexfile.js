//require('dotenv').config({ path: '../.env'});
const config = require('./config');
const setup = {
  client: "pg",
  connection: {
    host : config.DB_HOST,
    port : config.DB_PORT,
    database : config.DB_NAME,
    user : config.DB_USER,
    password : config.DB_PASS
  },
  pool: {
    max: (config.DB_MAX_POOL)?parseInt(config.DB_MAX_POOL):10,
    min: 2
  },
  migrations: {
    tableName: "knex_migrations",
  }
}

console.log("postgresql config", setup)

module.exports = {
  development: setup,
  production: setup
};
