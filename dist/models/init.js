'use strict';

var mongoose = require('mongoose');
var config = require('../config');

mongoose.connect(config.mongodbUrl, {
  useMongoClient: true
});
//# sourceMappingURL=init.js.map