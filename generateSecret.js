const crypto = require('crypto');

// Generate a 32-byte random secret and convert it to a hexadecimal string
const refreshTokenSecret = crypto.randomBytes(32).toString('hex');

console.log('Your JWT_REFRESH_SECRET:', refreshTokenSecret);
