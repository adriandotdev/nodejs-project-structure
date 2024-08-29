const axios = require("axios");

module.exports = class SMS {
	constructor(data) {
		this.data = data;
	}

	async SendOTP() {
		const result = await axios.get(
			`${this.data.contact_number}&text=${this.data.message}`,
			{
				headers: {
					Authorization: `Basic ${process.env.SMS_API_KEY}`,
				},
			}
		);

		return result;
	}
};
