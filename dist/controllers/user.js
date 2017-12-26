'use strict';

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.more = exports.signin = exports.signup = undefined;

var _bcrypt = require('bcrypt');

var _bcrypt2 = _interopRequireDefault(_bcrypt);

var _post = require('../models/post');

var _post2 = _interopRequireDefault(_post);

var _user = require('../models/user');

var _user2 = _interopRequireDefault(_user);

var _config = require('../config');

var _config2 = _interopRequireDefault(_config);

var _jwtSimple = require('jwt-simple');

var _jwtSimple2 = _interopRequireDefault(_jwtSimple);

var _moment = require('moment');

var _moment2 = _interopRequireDefault(_moment);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

var signup = exports.signup = function signup(req, res, next) {
  var _req$body = req.body,
      name = _req$body.name,
      pass = _req$body.pass,
      rePass = _req$body.rePass;


  if (pass !== rePass) {
    return next(new Error('两次密码不对'));
  }

  var user = new _user2.default();
  user.name = name;
  user.pass = _bcrypt2.default.hashSync(pass, 10);
  user.save().then(function () {
    res.end();
  }).catch(next);
};

var signin = exports.signin = function signin(req, res, next) {
  var _req$body2 = req.body,
      name = _req$body2.name,
      pass = _req$body2.pass;


  _user2.default.findOne({ name: name }).exec().then(function (user) {
    if (!user) {
      throw new Error('找不到用户');
    } else {
      var isOk = _bcrypt2.default.compareSync(pass, user.pass);
      if (!isOk) {
        return next(new Error('密码不对'));
      }

      var token = _jwtSimple2.default.encode({
        _id: user._id,
        name: user.name,
        isAdmin: user.loginname === _config2.default.admin,
        exp: (0, _moment2.default)().add('days', 30).valueOf()
      }, _config2.default.jwtSecret);

      var opts = {
        path: '/',
        maxAge: (0, _moment2.default)().add('days', 30).valueOf(),
        signed: true,
        httpOnly: true
      };

      res.cookie(_config2.default.cookieName, token, opts);
      res.json({ token: token });
    }
  }).catch(next);
};

var more = exports.more = function more(req, res, next) {
  res.send('respond with a resource');
};
//# sourceMappingURL=user.js.map