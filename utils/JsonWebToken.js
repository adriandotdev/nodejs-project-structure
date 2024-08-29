const jwt = require("jsonwebtoken");

module.exports = class JWT {
	static Sign(payload, secretKey) {
		return jwt.sign(payload, secretKey);
	}

	static Verify(token, secretKey, callback) {
		jwt.verify(token, secretKey, callback);
	}

	static Decode(token) {
		return jwt.decode(token);
	}
};
