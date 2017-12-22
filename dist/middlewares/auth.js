'use strict';

var config = require('../config');
var UserModel = require('../models/user');

function authUser(req, res, next) {
  res.locals.currentUser = null;

  if (req.session && req.session.user) {
    var user = req.session.user;
    res.locals.currentUser = user;
    next();
  } else {
    var authToken = req.signedCookies[config.cookieName] || '';

    if (authToken) {
      UserModel.findOne({ _id: authToken }, function (err, user) {
        if (err) {
          next();
        } else {
          if (user.loginname === config.admin) {
            user.isAdmin = true;
          }

          req.session.user = user;
          res.locals.currentUser = user;
          next();
        }
      });
    } else {
      next();
    }
  }
}

function adminRequired(req, res, next) {
  if (!req.session || !req.session.user) {
    var err = new Error('需要登录');
    err.status = 403;
    next(err);
    return;
  }

  if (!req.session.user.isAdmin) {
    var _err = new Error('需要管理员权限');
    _err.status = 403;
    next(_err);
    return;
  }

  next();
}

module.exports = { authUser: authUser, adminRequired: adminRequired };
//# sourceMappingURL=auth.js.map