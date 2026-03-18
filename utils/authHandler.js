let userController = require('../controllers/users');
let jwt = require('jsonwebtoken');
let fs = require('fs');
let path = require('path');

const publicKey = fs.readFileSync(path.join(__dirname, '../public.pem'), 'utf8');

module.exports = {
    CheckLogin: async function (req, res, next) {
        try {
            if (!req.headers.authorization || !req.headers.authorization.startsWith("Bearer")) {
                return res.status(401).send({ message: "Ban chua dang nhap" });
            }
            let token = req.headers.authorization.split(" ")[1];
            
            let result = jwt.verify(token, publicKey, { algorithms: ['RS256'] });

            let user = await userController.GetAnUserById(result.id);
            if (!user) {
                return res.status(401).send({ message: "User khong ton tai" });
            }
            req.user = user;
            next();
        } catch (error) {
            res.status(401).send({ message: "Token khong hop le hoac het han" });
        }
    }
}