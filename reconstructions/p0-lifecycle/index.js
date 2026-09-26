'use strict';
module.exports.format = (date) => new Date(date).toISOString().slice(0, 10);
