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

const encrypt = (text) => {
    const passphrase = '123';
    return CryptoJS.AES.encrypt(text, passphrase).toString();
};

const decrypt = (encripted_text) => {
    const passphrase = '123';
    const bytes = CryptoJS.AES.decrypt(ciphertext, passphrase);
    const originalText = bytes.toString(CryptoJS.enc.Utf8);
    return originalText;
};

module.exports = { getHashedPassword, checkPassword, getToken, verifyToken, encrypt, decrypt }