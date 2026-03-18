var express = require("express");
var router = express.Router();
let userController = require('../controllers/users');
let bcrypt = require('bcrypt');
let jwt = require('jsonwebtoken');
let fs = require('fs');
let path = require('path');
const { CheckLogin } = require("../utils/authHandler");

// Đọc Private Key
const privateKey = fs.readFileSync(path.join(__dirname, '../private.pem'), 'utf8');

router.post('/login', async function (req, res, next) {
    try {
        let { username, password } = req.body;
        let user = await userController.GetAnUserByUsername(username);
        if (!user) return res.status(404).send({ message: "thong tin dang nhap sai" });

        if (bcrypt.compareSync(password, user.password)) {
            let token = jwt.sign({ id: user._id }, privateKey, { 
                algorithm: 'RS256', 
                expiresIn: '1h' 
            });
            res.send(token);
        } else {
            res.status(404).send({ message: "thong tin dang nhap sai" });
        }
    } catch (error) {
        res.status(404).send({ message: error.message });
    }
});

router.post('/change-password', CheckLogin, async function (req, res) {
    try {
        let { oldpassword, newpassword } = req.body;
        let user = req.user; 

        if (!newpassword || newpassword.length < 6) {
            return res.status(400).send({ message: "Mat khau moi phai it nhat 6 ky tu" });
        }

        let isMatch = bcrypt.compareSync(oldpassword, user.password);
        if (!isMatch) {
            return res.status(400).send({ message: "Mat khau cu khong dung" });
        }

        user.password = newpassword; 
        
        await user.save();

        res.send({ message: "Doi mat khau thanh cong" });
    } catch (error) {
        res.status(500).send({ message: error.message });
    }
});

router.get('/me', CheckLogin, function(req, res) {
    res.send(req.user);
});

module.exports = router;