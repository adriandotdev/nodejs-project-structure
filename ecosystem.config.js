//config app for PM2
module.exports = {
	apps: [
		{
			name: "login:4001", //label
			script: "server.js", //entrypoint
		},
	],
};
