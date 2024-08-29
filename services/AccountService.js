/**
 * @author Adrian Marcelo
 * @description This file contains all of the services that can be used by the API.
 */

// External Packages
const otpGenerator = require("otp-generator");
const { v4: uuidv4 } = require("uuid");

// Repository
const AccountRepository = require("../repository/AccountRepository");

// Http Errors
const {
	HttpForbidden,
	HttpUnauthorized,
	HttpInternalServerError,
	HttpBadRequest,
} = require("../utils/HttpError");

// Json Web Token
const JWT = require("../utils/JsonWebToken");

const JsonWebToken = require("../utils/JsonWebToken");

// Config Files
const winston = require("../config/winston");

// Utilities
const Crypto = require("../utils/Crypto");
const Email = require("../utils/Email");
const SMS = require("../utils/SMS");

module.exports = class AccountService {
	/**
	 * @type {AccountRepository}
	 */
	#repository;

	constructor(repository) {
		this.#repository = repository;
	}

	/**
	 * Logs in a user with the provided username and password.
	 *
	 * This function verifies the user's credentials, generates access and refresh tokens upon successful login,
	 * and saves the tokens in the database. It also retrieves user privileges and logs the login action in the audit trail.
	 *
	 * @async
	 * @function Login
	 * @param {Object} credentials - The username and password of the user.
	 * @param {string} credentials.username - The username of the user.
	 * @param {string} credentials.password - The password of the user.
	 * @returns {Promise<Object>} A promise that resolves to an object containing authentication information including access and refresh tokens.
	 * @throws {HttpUnauthorized} If the provided credentials are invalid.
	 * @throws {Error} If an error occurs while processing the login.
	 */
	async Login({ username, password }) {
		// /**
		//  * @type {import("mysql2").PoolConnection}
		//  */
		let connection = null;

		try {
			connection = await this.#repository.GetConnection();

			connection.beginTransaction();

			const result = await this.#repository.Login(
				{ username, password },
				connection
			);

			/** If user is not found */
			if (result.length < 1) {
				winston.error({
					LOGIN_ACCOUNT_SERVICE: {
						message: "User Not Found",
					},
				});

				throw new HttpUnauthorized("Unauthorized", {
					message: "Invalid credentials",
				});
			}

			if (result[0].user_status === "INACTIVE")
				throw new HttpUnauthorized("ACCOUNT_IS_DEACTIVATED", []);

			// Access, and Refresh Token Expirations
			const accessTokenExpiration = Math.floor(Date.now() / 1000) + 60 * 15; // 15 mins
			const refreshTokenExpiration =
				Math.floor(Date.now() / 1000) + 60 * 60 * 24 * 30; // 1 month

			const data = {
				id: result[0].id,
				username,
				role: result[0].role,
				role_id: result[0].id,
				rfid_card_tag: result[0].rfid_card_tag,
			};

			const privileges = await this.#repository.GetUserPrivileges(
				data.id,
				connection
			);

			const access_token = JWT.Sign(
				{
					data,
					jti: uuidv4(),
					aud: "parkncharge-app",
					iss: "parkncharge",
					iat: Math.floor(Date.now() / 1000),
					typ: "Bearer",
					exp: accessTokenExpiration,
					usr: "serv",
				},
				process.env.JWT_ACCESS_KEY
			);

			const refresh_token = JWT.Sign(
				{
					data,
					jti: uuidv4(),
					aud: "parkncharge-app",
					iss: "parkncharge",
					iat: Math.floor(Date.now() / 1000),
					typ: "Bearer",
					exp: refreshTokenExpiration,
					usr: "serv",
				},
				process.env.JWT_REFRESH_KEY
			);

			const encryptedAccessTokenKey = Crypto.Encrypt(access_token);
			const encryptedRefreshTokenKey = Crypto.Encrypt(refresh_token);

			await this.#repository.UpdateLastActiveAccount(data.id, connection);

			await this.#repository.SaveAuthorizationInfo(
				{
					access_token,
					refresh_token,
					user_id: data.id,
				},
				connection
			);

			connection.commit();

			// If user's role is ADMIN, then audit trail
			if (
				["ADMIN_NOC", "ADMIN_MARKETING", "ADMIN_ACCOUNTING"].includes(data.role)
			) {
				await this.#repository.AuditTrail({
					admin_id: data.id,
					cpo_id: null,
					action: `Login - User with ID of ${data.id}`,
					remarks: "success",
				});
			}

			// If user's role is CPO_OWNER, then audit trail
			if (["CPO_OWNER"].includes(data.role)) {
				await this.#repository.AuditTrail({
					admin_id: null,
					cpo_id: data.id,
					action: `Login - User with ID of ${data.id}`,
					remarks: "success",
				});
			}

			const samplePriv = { user_id: privileges[0]?.user_id };

			if (samplePriv.user_id) {
				Object.entries(privileges[0]).map((value) => {
					if (value[1] === 1) samplePriv[value[0]] = value[1];
				});
			}

			return {
				access_token: encryptedAccessTokenKey,
				access_expires_in: accessTokenExpiration,
				refresh_token: encryptedRefreshTokenKey,
				refresh_expires_in: refreshTokenExpiration,
				privileges: privileges && { ...samplePriv },
				role: data.role,
			};
		} catch (err) {
			if (connection) connection.rollback();
			throw err;
		} finally {
			if (connection) connection.release();
		}
	}

	/**
	 * Logs out a user by invalidating the provided access token.
	 *
	 * This function invalidates the access token associated with the specified user ID,
	 * thereby logging the user out of the system. It also logs the logout action in the audit trail.
	 *
	 * @async
	 * @function Logout
	 * @param {string} userID - The ID of the user to logout.
	 * @param {string} accessToken - The access token to invalidate.
	 * @throws {Error} If an error occurs while logging out the user.
	 */
	async Logout(userID, accessToken) {
		try {
			await this.#repository.Logout(userID, accessToken);

			const result = await this.#repository.GetUserRoleByID(userID);

			const role = result[0].role;

			if (["ADMIN_NOC", "ADMIN_MARKETING", "ADMIN_ACCOUNTING"].includes(role)) {
				await this.#repository.AuditTrail({
					admin_id: userID,
					cpo_id: null,
					action: `Logout - User with ID of ${userID}`,
					remarks: "success",
				});
			}

			if (["CPO_OWNER"].includes(role)) {
				await this.#repository.AuditTrail({
					admin_id: null,
					cpo_id: userID,
					action: `Logout - User with ID of ${userID}`,
					remarks: "success",
				});
			}

			await this.#repository.UpdateLastActiveAccount(userID, null);
		} catch (err) {
			throw err;
		}
	}

	/**
	 * Generates a new pair of access and refresh tokens based on the provided refresh token.
	 *
	 * This function decodes the provided refresh token, generates new access and refresh tokens,
	 * updates the authorization information in the database, and returns the new tokens.
	 *
	 * @async
	 * @function GenerateNewRefreshToken
	 * @param {string} refreshToken - The refresh token used to generate new tokens.
	 * @returns {Promise<Object>} A promise that resolves to an object containing the new access and refresh tokens.
	 * @throws {Error} If an error occurs while generating new tokens.
	 */
	async GenerateNewRefreshToken(refreshToken) {
		try {
			const decode = JsonWebToken.Decode(refreshToken);

			// Access, and Refresh Token Expirations
			const accessTokenExpiration = Math.floor(Date.now() / 1000) + 60 * 15; // 15 mins
			const refreshTokenExpiration =
				Math.floor(Date.now() / 1000) + 60 * 60 * 24 * 30; // 1 month

			const data = {
				id: decode.data.id,
				username: decode.data.username,
				role: decode.data.role,
				role_id: decode.data.role_id,
				rfid_card_tag: decode.data.rfid_card_tag,
			};

			const access_token = JWT.Sign(
				{
					data,
					jti: uuidv4(),
					aud: "parkncharge-app",
					iss: "parkncharge",
					iat: Math.floor(Date.now() / 1000),
					typ: "Bearer",
					exp: accessTokenExpiration,
					usr: "serv",
				},
				process.env.JWT_ACCESS_KEY
			);

			const refresh_token = JWT.Sign(
				{
					data,
					jti: uuidv4(),
					aud: "parkncharge-app",
					iss: "parkncharge",
					iat: Math.floor(Date.now() / 1000),
					typ: "Bearer",
					exp: refreshTokenExpiration,
					usr: "serv",
				},
				process.env.JWT_REFRESH_KEY
			);

			const encryptedAccessTokenKey = Crypto.Encrypt(access_token);
			const encryptedRefreshTokenKey = Crypto.Encrypt(refresh_token);

			await this.#repository.UpdateAuthorizationInfo({
				user_id: data.id,
				new_access_token: access_token,
				new_refresh_token: refresh_token,
				prev_refresh_token: refreshToken,
			});

			return {
				access_token: encryptedAccessTokenKey,
				access_expires_in: accessTokenExpiration,
				refresh_token: encryptedRefreshTokenKey,
				refresh_expires_in: refreshTokenExpiration,
			};
		} catch (err) {
			throw err;
		}
	}

	/**
	 * Sends an OTP (One-Time Password) to the provided email address.
	 *
	 * This function generates an OTP, encrypts the email address, generates a token for the OTP,
	 * and sends an email containing the OTP to the provided email address. It then returns the status
	 * of the OTP sending operation along with the generated OTP.
	 *
	 * @async
	 * @function SendOTP
	 * @param {string} email - The email address to which the OTP will be sent.
	 * @returns {Promise<Object>} A promise that resolves to an object containing the status of the OTP sending operation and the generated OTP.
	 * @throws {Error} If an error occurs while sending the OTP.
	 */
	async SendOTP(email) {
		try {
			const encryptedEmail = Crypto.Encrypt(email);

			const token_expiration = Math.floor(Date.now() / 1000) + 60 * 2;

			const token = JsonWebToken.Sign(
				{
					data: "otp-token",
					exp: token_expiration,
				},
				"otp-secretkey"
			);

			const otp = otpGenerator.generate(6, {
				upperCaseAlphabets: false,
				specialChars: false,
				lowerCaseAlphabets: false,
				digits: true,
			});

			const result = await this.#repository.SendOTP({
				email: encryptedEmail,
				otp,
				token,
				token_expiration,
			});

			const status = result[0][0].STATUS;

			if (status === "INVALID_RESEND_COUNT")
				throw new HttpForbidden(
					"Maximum attempts of sending OTPs has been reached",
					status
				);

			if (status === "EMAIL_DOES_NOT_EXISTS")
				throw new HttpForbidden("Email does not exists", status);

			// console.log(status);
			const emailSender = new Email(email, { otp });

			await emailSender.SendOTP();

			return { ...result[0][0], otp };
		} catch (err) {
			throw err;
		}
	}

	/**
	 * Verifies the provided OTP (One-Time Password) for a user.
	 *
	 * This function verifies the OTP provided by the user against the stored OTP
	 * for the given user ID. It also checks the status of the OTP verification
	 * operation and ensures that the OTP has not expired. If the OTP is incorrect,
	 * has reached maximum verification attempts, or has expired, appropriate error
	 * responses are thrown.
	 *
	 * @async
	 * @function VerifyOTP
	 * @param {string} user_id - The ID of the user for whom OTP verification is being performed.
	 * @param {string} otp - The OTP provided by the user for verification.
	 * @returns {Promise<string>} A promise that resolves to a string representing the status of the OTP verification operation.
	 * @throws {HttpUnauthorized} If the provided OTP is incorrect or has expired.
	 * @throws {HttpForbidden} If maximum attempts of verifying OTP has been reached.
	 * @throws {Error} If an error occurs during OTP verification.
	 */
	async VerifyOTP({ user_id, otp }) {
		try {
			const result = await this.#repository.VerifyOTP({ user_id, otp });

			const status = result[0][0].STATUS;

			if (status === "OTP_IS_INCORRECT") {
				throw new HttpUnauthorized("Incorrect OTP", status);
			}

			if (status === "INVALID") {
				throw new HttpForbidden(
					"Maximum attempts of verfying OTP has been reached",
					status
				);
			}

			const token = result[0][0].TOKEN;

			try {
				JsonWebToken.Verify(token, "otp-secretkey");
			} catch (err) {
				throw new HttpUnauthorized("OTP Expired", "OTP Expired");
			}
			return status;
		} catch (err) {
			throw err;
		}
	}

	/**
	 * Changes the password for the specified user.
	 *
	 * This function changes the password for the user identified by the provided user ID.
	 * It interacts with the repository to perform the password change operation and handles
	 * the response accordingly. If the user ID does not exist, an error response is thrown.
	 *
	 * @async
	 * @function ChangePassword
	 * @param {string} password - The new password to be set for the user.
	 * @param {string} user_id - The ID of the user for whom the password is being changed.
	 * @returns {Promise<string>} A promise that resolves to a string representing the status of the password change operation.
	 * @throws {HttpUnauthorized} If the user ID does not exist.
	 * @throws {Error} If an error occurs during the password change operation.
	 */
	async ChangePassword({ password, user_id }) {
		try {
			const response = await this.#repository.ChangePassword({
				password,
				user_id,
			});

			const status = response[0][0].STATUS;

			if (status === "USER_ID_DOES_NOT_EXISTS")
				throw new HttpUnauthorized("Unauthorized", {
					message: "User ID does not exists",
				});

			await this.#repository.UpdateLastActiveAccount(user_id, null);

			return status;
		} catch (err) {
			throw err;
		}
	}

	/**
	 * Changes the old password to a new password for a user.
	 *
	 * This function attempts to change the old password to a new password for the user
	 * based on the provided payload. It interacts with the repository to perform the
	 * password change operation and handles the response accordingly. If the old password
	 * is incorrect or the new password does not match, specific error responses are thrown.
	 *
	 * @async
	 * @function ChangeOldPassword
	 * @param {Object} payload - An object containing the payload data for changing the password.
	 * @param {string} payload.user_id - The ID of the user for whom the password is being changed.
	 * @param {string} payload.old_password - The old password.
	 * @param {string} payload.new_password - The new password.
	 * @param {string} payload.confirm_password - The confirmation of the new password.
	 * @returns {Promise<string>} A promise that resolves to a string representing the status of the password change operation.
	 * @throws {HttpBadRequest} If the old password is incorrect or the new password does not match.
	 * @throws {Error} If an error occurs during the password change operation.
	 */
	async ChangeOldPassword(payload) {
		try {
			const result = await this.#repository.ChangeOldPassword({ ...payload });

			const STATUS = result[0][0].STATUS;

			switch (STATUS) {
				case "INCORRECT_OLD_PASSWORD":
					throw new HttpBadRequest(STATUS, []);
				case "NEW_PASSWORD_DOES_NOT_MATCH":
					throw new HttpBadRequest(STATUS, []);
				default:
					await this.#repository.UpdateLastActiveAccount(payload.user_id, null);
					return "SUCCESS";
			}
		} catch (err) {
			throw err;
		}
	}

	/**
	 * Retrieves details of a user by their ID.
	 *
	 * This function retrieves details of a user identified by the provided userID.
	 * It interacts with the repository to fetch user details and decrypts sensitive
	 * information such as name, email, address, and mobile number before returning
	 * the user details.
	 *
	 * @async
	 * @function GetUserDetails
	 * @param {string} userID - The ID of the user whose details are to be retrieved.
	 * @returns {Promise<Object>} A promise that resolves to an object containing the user details.
	 * @throws {Error} If an error occurs while fetching or decrypting user details.
	 */
	async GetUserDetails(userID) {
		try {
			const result = await this.#repository.GetUserDetails(userID);

			const userInfo = result[0];

			const details = {
				user_id: userInfo.user_id,
				user_driver_id: userInfo.user_driver_id,
				username: userInfo.username,
				role: userInfo.role,
				name: Crypto.Decrypt(userInfo.name),
				email: Crypto.Decrypt(userInfo.email),
				address: Crypto.Decrypt(userInfo.address),
				mobile_number: Crypto.Decrypt(userInfo.mobile_number),
				rfid_card_tag: userInfo.rfid_card_tag,
				balance: userInfo.balance,
			};

			return details;
		} catch (err) {
			throw err;
		}
	}
};
