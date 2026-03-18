var express = require("express");
var router = express.Router();
let userController = require('../controllers/users');
let bcrypt = require('bcrypt');
let jwt = require('jsonwebtoken');
let fs = require('fs');
let path = require('path');
const { CheckLogin } = require("../utils/authHandler");

const privateKey = fs.readFileSync(path.join(__dirname, '../private.pem'), 'utf8');

router.post('/register', async function (req, res, next) {
    try {
        let { username, password, email } = req.body;
        
        let roleId = "69b0d30bf0737b9f65ed1335"; 

        let newUser = await userController.CreateAnUser(
            username, 
            password,
            email, 
            roleId
        );
        
        res.send(newUser);
    } catch (error) {
        res.status(400).send({ message: error.message });
    }
});

router.post('/login', async function (req, res, next) {
    try {
        let { username, password } = req.body;
        let user = await userController.GetAnUserByUsername(username);
        
        if (!user) {
            return res.status(404).send({ message: "Thong tin dang nhap sai" });
        }

        if (user.lockTime > Date.now()) {
            return res.status(403).send({ message: "Tai khoan dang bi tam khoa" });
        }

        if (bcrypt.compareSync(password, user.password)) {
            user.loginCount = 0;
            await user.save();

            let token = jwt.sign({ id: user._id }, privateKey, { 
                algorithm: 'RS256', 
                expiresIn: '1h' 
            });
            res.send(token);
        } else {
            user.loginCount = (user.loginCount || 0) + 1;
            if (user.loginCount >= 3) {
                user.loginCount = 0;
                user.lockTime = Date.now() + 3600 * 1000;
            }
            await user.save();
            res.status(404).send({ message: "Thong tin dang nhap sai" });
        }
    } catch (error) {
        res.status(500).send({ message: error.message });
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