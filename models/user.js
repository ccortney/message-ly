/** User class for message.ly */

const bcrypt = require('bcrypt');
const {BCRYPT_WORK_FACTOR} = require('../config.js')
const db = require("../db");

/** User of the site. */

class User {

  /** register new user -- returns
   *    {username, password, first_name, last_name, phone}
   */
  static async register({username, password, first_name, last_name, phone}) { 
    // hash password
    const hashedPassword = await bcrypt.hash(password, BCRYPT_WORK_FACTOR);
    // save to DB
    const result = await db.query(`
      INSERT INTO users (username, password, first_name, last_name, phone, join_at, last_login_at)
      VALUES ($1, $2, $3, $4, $5, current_timestamp, current_timestamp)
      RETURNING username, password, first_name, last_name, phone`, 
      [username, hashedPassword, first_name, last_name, phone]);
    return result.rows[0];
  }
   

  /** Authenticate: is this username/password valid? Returns boolean. */

  static async authenticate(username, password) { 
    const result = await db.query(`
    SELECT username, password
    FROM users
    WHERE username = $1`, [username]);
    
    const user = result.rows[0];
    if (user) {
      if (await bcrypt.compare(password, user.password)) {
        return true
      }
      return false
    }
  }

  /** Update last_login_at for user */

  static async updateLoginTimestamp(username) {
    const result = await db.query(`
    UPDATE users SET last_login_at = current_timestamp
    WHERE username = $1`, [username]);
    return result.rows[0]
   }

  /** All: basic info on all users:
   * [{username, first_name, last_name, phone}, ...] */

  static async all() {
    const results = await db.query(`
    SELECT username, first_name, last_name, phone
    FROM users`);
    return results.rows
  }

  /** Get: get user by username
   *
   * returns {username,
   *          first_name,
   *          last_name,
   *          phone,
   *          join_at,
   *          last_login_at } */

  static async get(username) { 
    const result = await db.query(`
    SELECT username, first_name, last_name, phone, join_at, last_login_at
    FROM users
    WHERE username = $1`, [username]);
    return result.rows[0]
  }


  /** Return messages from this user.
   *
   * [{id, to_user, body, sent_at, read_at}]
   *
   * where to_user is
   *   {username, first_name, last_name, phone}
   */

  static async messagesFrom(username) { 
    const results = await db.query(`
    SELECT 
      m.id, 
      m.to_username, 
      m.body, 
      m.sent_at, 
      m.read_at, 
      u.first_name, 
      u.last_name,
      u.phone
    FROM messages AS m
    INNER JOIN users AS u ON (m.to_username = u.username)
    WHERE m.from_username = $1
    `, [username]);
    let messages = [];
    
    for (let row of results.rows) {
      let message = {
        id: row.id,
        body: row.body,
        sent_at: row.sent_at,
        read_at: row.read_at
      };
      let user = {
        username: row.to_username,
        first_name: row.first_name,
        last_name: row.last_name,
        phone: row.phone 
      };
      message.to_user = user;
      messages.push(message);
    }
    return messages;
  }


  /** Return messages to this user.
   *
   * [{id, from_user, body, sent_at, read_at}]
   *
   * where from_user is
   *   {username, first_name, last_name, phone}
   */

  static async messagesTo(username) {
    const results = await db.query(`
    SELECT 
      m.id, 
      m.from_username, 
      m.body, 
      m.sent_at, 
      m.read_at, 
      u.first_name, 
      u.last_name,
      u.phone
    FROM messages AS m
    INNER JOIN users AS u ON (m.from_username = u.username)
    WHERE m.to_username = $1
    `, [username]);
    let messages = [];
    
    for (let row of results.rows) {
      let message = {
        id: row.id,
        body: row.body,
        sent_at: row.sent_at,
        read_at: row.read_at
      };
      let user = {
        username: row.from_username,
        first_name: row.first_name,
        last_name: row.last_name,
        phone: row.phone 
      };
      message.from_user = user;
      messages.push(message);
    }
    return messages;
   }
}


module.exports = User;