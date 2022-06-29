const CryptoJS = require('crypto-js')
const bcrypt = require('bcrypt')
const jwt = require("jsonwebtoken")

const secret = 'p4ssw0rd'

const getHashedPassword = (password) => {
    return bcrypt.hashSync(password, bcrypt.genSaltSync(10))
}

const checkPassword = (password, hash) => {
    return bcrypt.compareSync(password, hash);
}

const getToken = (user) => {
    return jwt.sign({
        username: user.username
    }, secret, { expiresIn: '2h' });
}

function verifyToken(token) {
    jwt.verify(token, secret, (err, user) => {
        if (err) {
            return false
        }
        return true
    })
};

module.exports = { getHashedPassword, checkPassword, getToken, verifyToken }