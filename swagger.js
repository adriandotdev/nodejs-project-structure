const swaggerJSDoc = require("swagger-jsdoc");

const swaggerDefinition = {
	openapi: "3.0.0",
	info: {
		title: "API Title",
		version: "1.0.0",
		description: "This document contains all of the Login service APIs ",
	},
};

const options = {
	swaggerDefinition,
	apis: ["./api/account.api.js"], // Path to the API routes in your Node.js application
};

const swaggerSpec = swaggerJSDoc(options);
module.exports = swaggerSpec;
