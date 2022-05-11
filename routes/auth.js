const express = require("express");
const jwt = require("jsonwebtoken");
const { SECRET_KEY } = require("../config");
const router = new express.Router();
const ExpressError = require("../expressError");
const User = require("../models/user");

/** POST /login - login: {username, password} => {token}
 *
 * Make sure to update their last-login!
 *
 **/

router.post('/login', async function(req, res, next) {
    try{
        const {username, password} = req.body;
        if (!username || !password) {
            throw new ExpressError("Username and password required", 400);
        }
        const authenticated = await User.authenticate(username, password);
        if (authenticated) {
            const token = jwt.sign({username}, SECRET_KEY);
            await User.updateLoginTimestamp(username);
            return res.json({message: "Logged In!", token})
        }
        throw new ExpressError ("Invalid username/password", 400)
    } catch (err) {
        return next (err);
    }
})


/** POST /register - register user: registers, logs in, and returns token.
 *
 * {username, password, first_name, last_name, phone} => {token}.
 *
 *  Make sure to update their last-login!
 */

router.post('/register', async function(req, res, next) {
    try{
        const {username, password, first_name, last_name, phone} = req.body;
        if (!username || !password || !last_name || !first_name || !phone) {
            throw new ExpressError("All fields required", 400);
        }
        const registered = await User.register({username, password, first_name, last_name, phone});
        if (registered) {
            const a = await User.authenticate(username, password);  
            const token = jwt.sign({username}, SECRET_KEY);
            await User.updateLoginTimestamp(username);
            return res.json({token})
        }
        throw new ExpressError ("Error creating your account", 400)
    } catch(err) {
        return next(err);
    }
})


module.exports = router;