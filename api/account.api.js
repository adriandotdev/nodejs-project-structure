/**
 * @Author Adrian Marcelo
 *
 * This file contains all of the APIs for user accounts such as:
 * - Login
 * - Logout
 * - Forgot Password
 * - Send OTP
 * - Verify OTP
 */

// External Packages
const { validationResult, body, param } = require("express-validator");

// Service
const AccountService = require("../services/AccountService");

// Repository
const AccountRepository = require("../repository/AccountRepository");

// HttpErrors
const { HttpUnprocessableEntity } = require("../utils/HttpError");

// Config Files
const logger = require("../config/winston");

// Midlewares
const TokenMiddleware = require("../middlewares/TokenMiddleware");

// Utilities
const JsonWebToken = require("../utils/JsonWebToken");
const Crypto = require("../utils/Crypto");

/**
 * @param {import('express').Express} app
 */
module.exports = (app) => {
	const service = new AccountService(new AccountRepository());
	const tokenMiddleware = new TokenMiddleware();
	/**
	 * This function will be used by the express-validator for input validation,
	 * and to be attached to APIs middleware.
	 * @param {*} req
	 * @param {*} res
	 */
	function validate(req, res) {
		const ERRORS = validationResult(req);

		if (!ERRORS.isEmpty()) {
			throw new HttpUnprocessableEntity(
				"Unprocessable Entity",
				ERRORS.mapped()
			);
		}
	}

	/**
	 * Login API
	 *
	 * @API /api/auth/v1/login
	 *
	 * This API will be used to authenticate the user by providing their username, and password.
	 */
	app.post(
		"/login/api/auth/v1/login",
		[
			tokenMiddleware.BasicTokenVerifier(),
			body("username")
				.notEmpty()
				.escape()
				.withMessage("Missing required property: username"),
			body("password")
				.notEmpty()
				.escape()
				.withMessage("Missing required property: password"),
		],

		/**
		 * @param {import('express').Request} req
		 * @param {import('express').Response} res
		 * @param {import('express').NextFunction} next
		 */
		async (req, res, next) => {
			const { username, password } = req.body;

			try {
				logger.info({
					LOGIN_API_REQUEST: {
						data: {
							username,
							password,
						},
					},
				});

				validate(req, res);

				const data = await service.Login({ username, password });

				logger.info({ LOGIN_API_RESPONSE: { data } });

				return res.status(200).json({ status: 200, data, message: "SUCCESS" });
			} catch (err) {
				req.error_name = "LOGIN_API_ERROR";
				next(err);
			}
		}
	);

	/**
	 * Logout API
	 *
	 * @API /api/auth/v1/logout */

	app.post(
		"/login/api/auth/v1/logout",
		tokenMiddleware.AccessTokenVerifier(),
		/**
		 * @param {import('express').Request} req
		 * @param {import('express').Response} res
		 * @param {import('express').NextFunction} next
		 */
		async (req, res, next) => {
			try {
				logger.info({
					LOGOUT_API_REQUEST: {
						data: {
							id: req.id,
							access_token: req.access_token ? "present" : "not found",
						},
					},
				});

				await service.Logout(req.id, req.access_token);

				logger.info({
					LOGOUT_API_RESPONSE: {
						message: "Logged out successfully",
					},
				});

				return res
					.status(200)
					.json({ status: 200, data: [], message: "Logged out successfully" });
			} catch (err) {
				req.error_name = "LOGOUT_API_ERROR";
				next(err);
			}
		}
	);

	app.get(
		"/login/api/auth/v1/refresh",
		tokenMiddleware.RefreshTokenVerifier(),
		/**
		 * @param {import('express').Request} req
		 * @param {import('express').Response} res
		 * @param {import('express').NextFunction} next
		 */
		async (req, res, next) => {
			try {
				logger.info({
					REFRESH_TOKEN_API_REQUEST: {
						data: {
							username: req.username,
							refresh_token: req.refresh_token ? "present" : "not found",
						},
					},
				});

				const response = await service.GenerateNewRefreshToken(
					req.refresh_token
				);

				logger.info({
					REFRESH_TOKEN_API_RESPONSE: {
						message: "Success",
						data: response,
					},
				});
				return res
					.status(200)
					.json({ status: 200, data: response, message: "Success" });
			} catch (err) {
				req.error_name = "REFRESH_TOKEN_API_ERROR";
				next(err);
			}
		}
	);

	app.post(
		"/login/api/auth/v1/send-otp",
		[
			tokenMiddleware.BasicTokenVerifier(),
			body("email").notEmpty().withMessage("Missing required property: email"),
		],
		/**
		 * @param {import('express').Request} req
		 * @param {import('express').Response} res
		 * @param {import('express').NextFunction} next
		 */
		async (req, res, next) => {
			const { email } = req.body;

			try {
				logger.info({
					SEND_OTP_API_REQUEST: {
						data: { email },
						message: "SUCCESS",
					},
				});

				validate(req, res);

				const response = await service.SendOTP(
					email.trim().replace(/\s+/gi, "")
				);

				logger.info({
					SEND_OTP_API_RESPONSE: {
						user_id: response.USER_ID,
						status: response.STATUS,
					},
				});
				return res.json({ status: 200, data: response, message: "Success" });
			} catch (err) {
				req.error_name = "SEND_OTP_API_ERROR";
				next(err);
			}
		}
	);

	app.post(
		"/login/api/auth/v1/verify-otp",
		[
			tokenMiddleware.BasicTokenVerifier(),
			body("user_id")
				.notEmpty()
				.escape()
				.withMessage("Missing required property: user_id")
				.custom((value) => typeof value === "string")
				.withMessage("Property user_id must be in type of number")
				.custom(
					(value) =>
						parseInt(value) == value && typeof parseInt(value) === "number"
				)
				.withMessage("Property user_id must be in type of number"),
			body("otp")
				.notEmpty()
				.escape()
				.withMessage("Missing required property: otp")
				.custom(
					(value) =>
						typeof parseInt(value) === "number" && String(value).length === 6
				)
				.withMessage(
					"Property otp must be in number type with a length of six (6) digits"
				),
		],
		/**
		 * @param {import('express').Request} req
		 * @param {import('express').Response} res
		 * @param {import('express').NextFunction} next
		 */
		async (req, res, next) => {
			const { user_id, otp } = req.body;

			try {
				logger.info({
					VERIFY_OTP_API_REQUEST: {
						data: { user_id, otp },
						message: "SUCCESS",
					},
				});

				validate(req, res);

				const response = await service.VerifyOTP({ user_id, otp });

				logger.info({
					VERIFY_OTP_API_RESPONSE: {
						message: "Correct OTP",
					},
				});
				return res
					.status(200)
					.json({ status: 200, data: response, message: "Success" });
			} catch (err) {
				req.error_name = "VERIFY_OTP_API_ERROR";
				next(err);
			}
		}
	);

	app.post(
		"/login/api/auth/v1/change-password/:user_id",
		[
			tokenMiddleware.BasicTokenVerifier(),
			body("password")
				.notEmpty()
				.withMessage("Missing required property: password")
				.isLength({ min: 8 })
				.withMessage(
					"Required property: password must be atleast eight (8) characters long."
				)
				.custom((value) => String(value).match(/^[a-zA-Z0-9]+$/))
				.withMessage("Property password only accepts alphanumeric values"),
			param("user_id")
				.notEmpty()
				.withMessage("Missing required property: user_id")
				.custom(
					(value) =>
						parseInt(value) == value && typeof parseInt(value) === "number"
				)
				.withMessage("Property user_id must be in type of number"),
		],
		/**
		 * @param {import('express').Request} req
		 * @param {import('express').Response} res
		 * @param {import('express').NextFunction} next
		 */
		async (req, res, next) => {
			const { user_id } = req.params;
			const { password } = req.body;

			try {
				logger.info({
					CHANGE_PASSWORD_API_REQUEST: {
						data: {
							user_id,
							password,
						},
						message: "SUCCESS",
					},
				});

				validate(req, res);

				const response = await service.ChangePassword({
					password,
					user_id,
				});

				logger.info({
					CHANGE_PASSWORD_API_RESPONSE: {
						message: "SUCCESS",
					},
				});

				return res.status(200).json({
					status: 200,
					data: [{ status: response }],
					message: "Success",
				});
			} catch (err) {
				req.error_name = "CHANGE_PASSWORD_API_ERROR";
				next(err);
			}
		}
	);

	app.post(
		"/login/api/auth/v1/change-old-password",
		[
			tokenMiddleware.AccessTokenVerifier(),
			body("old_password")
				.notEmpty()
				.escape()
				.withMessage("Missing required property: old_password")
				.custom((value) => String(value).match(/^[a-zA-Z0-9]+$/))
				.withMessage("Property old_password only accepts alphanumeric values"),
			body("new_password")
				.notEmpty()
				.escape()
				.withMessage("Missing required property: new_password")
				.custom((value) => String(value).match(/^[a-zA-Z0-9]+$/))
				.withMessage("Property new_password only accepts alphanumeric values"),
			body("confirm_password")
				.notEmpty()
				.escape()
				.withMessage("Missing required property: confirm_password")
				.custom((value) => String(value).match(/^[a-zA-Z0-9]+$/))
				.withMessage(
					"Property confirm_password only accepts alphanumeric values"
				),
		],
		/**
		 * @param {import('express').Request} req
		 * @param {import('express').Response} res
		 * @param {import('express').NextFunction} next
		 */
		async (req, res, next) => {
			try {
				logger.info({
					CHANGE_OLD_PASSWORD_API_REQUEST: { message: "SUCCESS" },
				});

				validate(req, res);

				const result = await service.ChangeOldPassword({
					user_id: req.id,
					...req.body,
				});

				logger.info({
					CHANGE_OLD_PASSWORD_API_RESPONSE: {
						message: "SUCCESS",
					},
				});

				return res.status(200).json({ status: 200, message: result });
			} catch (err) {
				req.error_name = "CHANGE_OLD_PASSWORD_API_ERROR";
				next(err);
			}
		}
	);

	app.get(
		"/login/api/v1/accounts/users/info",
		[tokenMiddleware.AccessTokenVerifier()],

		/**
		 * @param {import('express').Request} req
		 * @param {import('express').Response} res
		 * @param {import('express').NextFunction} next
		 */
		async (req, res, next) => {
			try {
				logger.info({
					USER_ACCOUNT_INFORMATION_REQUEST: {
						data: {
							user_id: req.id,
						},
						message: "SUCCESS",
					},
				});

				const result = await service.GetUserDetails(req.id);

				logger.info({
					USER_ACCOUNT_INFORMATION_RESPONSE: {
						message: "SUCCESS",
					},
				});
				return res
					.status(200)
					.json({ status: 200, data: result, message: "Success" });
			} catch (err) {
				req.error_name = "USER_ACCOUNT_INFORMATION_ERROR";
				next(err);
			}
		}
	);

	app.use((err, req, res, next) => {
		logger.error({
			API_REQUEST_ERROR: {
				error_name: req.error_name || "UNKNOWN_ERROR",
				message: err.message,
				stack: err.stack.replace(/\\/g, "/"), // Include stack trace for debugging
				request: {
					method: req.method,
					url: req.url,
					code: err.status || 500,
				},
				data: err.data || [],
			},
		});

		const status = err.status || 500;
		const message = err.message || "Internal Server Error";

		res.status(status).json({
			status,
			data: err.data || [],
			message,
		});
	});
};
