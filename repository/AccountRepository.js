/**
 * @author Adrian Marcelo
 * @description This file contains all of the methods that directly interacts in the persistence layer.
 * All of the methods here can be used by the service layer.
 */
const mysql = require("../database/mysql");

module.exports = class AccountRepository {
	/**
	 * Establishes a database connection and begins a transaction.
	 *
	 * This function retrieves a database connection from the connection pool, begins a transaction,
	 * and returns the connection object. It allows performing multiple database operations within
	 * a single transaction to ensure data integrity.
	 *
	 * @function GetConnection
	 * @returns {Promise<Connection>} A promise that resolves to a database connection object with an active transaction.
	 */
	GetConnection() {
		return new Promise((resolve, reject) => {
			mysql.getConnection((err, connection) => {
				if (err) {
					reject(err);
				}

				resolve(connection);
			});
		});
	}

	/**
	 * Verifies a basic access token (username and password) against the database.
	 *
	 * This function verifies the provided username and password combination against the database
	 * to authenticate the user's access. It calls a stored procedure to perform the verification
	 * and returns the result.
	 *
	 * @function VerifyBasicToken
	 * @param {string} username - The username to verify.
	 * @param {string} password - The password associated with the username.
	 * @returns {Promise<any>} A promise that resolves to the result of the verification process.
	 */
	VerifyBasicToken(username, password) {
		const QUERY = `call WEB_USER_VERIFY_BASIC_TOKEN(?,?)`;

		return new Promise((resolve, reject) => {
			mysql.query(QUERY, [username, password], (err, result) => {
				if (err) {
					reject(err);
				}

				resolve(result);
			});
		});
	}

	/**
	 * Logs in a user by verifying the provided username and password against the database.
	 *
	 * This function is responsible for logging in a user by verifying the provided username and password
	 * combination against the database. It performs a query to retrieve user information based on the
	 * provided credentials.
	 *
	 * @function Login
	 * @param {Object} credentials - An object containing the username and password for authentication.
	 * @param {string} credentials.username - The username of the user attempting to log in.
	 * @param {string} credentials.password - The password associated with the username.
	 * @param {object} connection - The MySQL database connection object.
	 * @returns {Promise<any>} A promise that resolves to the result of the login attempt, including user information if successful.
	 */
	Login({ username, password }, connection) {
		const QUERY = `
			SELECT 
				users.id, 
				users.username, 
				users.password, 
				users.role,
				users.user_status,
				rfid_cards.rfid_card_tag 
			FROM 
				users 
			LEFT JOIN user_drivers ON users.id = user_drivers.user_id
			LEFT JOIN rfid_cards ON rfid_cards.user_driver_id = user_drivers.id
			WHERE username = ? AND password = MD5(?)
		`;
		return new Promise((resolve, reject) => {
			connection.query(QUERY, [username, password], (err, result) => {
				if (err) reject(err);

				resolve(result);
			});
		});
	}

	/**
	 * Retrieves user privileges based on the user ID.
	 *
	 * This function fetches user privileges from the database based on the provided user ID. It executes
	 * a query to retrieve all privileges associated with the specified user.
	 *
	 * @function GetUserPrivileges
	 * @param {number} id - The ID of the user whose privileges are to be retrieved.
	 * @param {object} connection - The MySQL database connection object.
	 * @returns {Promise<Array>} A promise that resolves to an array containing the user's privileges.
	 */
	GetUserPrivileges(id, connection) {
		const QUERY = `
			SELECT 
				* 
			FROM 
				user_privileges 
			WHERE user_id = ?
		`;

		return new Promise((resolve, reject) => {
			connection.query(QUERY, [id], (err, result) => {
				if (err) {
					reject(err);
				}

				resolve(result);
			});
		});
	}

	/**
	 * Finds an access token in the database.
	 *
	 * This function searches for an access token in the database based on the provided access token string.
	 *
	 * @function FindAccessToken
	 * @param {string} accessToken - The access token to search for.
	 * @returns {Promise<Array>} A promise that resolves to an array containing the access token if found.
	 */
	FindAccessToken(accessToken) {
		const QUERY = `SELECT access_token FROM authorization_tokens WHERE access_token = ?`;

		return new Promise((resolve, reject) => {
			mysql.query(QUERY, [accessToken], (err, result) => {
				if (err) {
					reject(err);
				}

				resolve(result);
			});
		});
	}

	/**
	 * Finds a refresh token in the database.
	 *
	 * This function searches for a refresh token in the database based on the provided refresh token string.
	 *
	 * @function FindRefreshToken
	 * @param {string} refreshToken - The refresh token to search for.
	 * @returns {Promise<Array>} A promise that resolves to an array containing the refresh token if found.
	 */
	FindRefreshToken(refreshToken) {
		const QUERY = `
			SELECT 
				refresh_token 
			FROM 
				authorization_tokens 
			WHERE refresh_token = ?`;

		return new Promise((resolve, reject) => {
			mysql.query(QUERY, [refreshToken], (err, result) => {
				if (err) {
					reject(err);
				}

				resolve(result);
			});
		});
	}

	/**
	 * Deletes refresh tokens associated with a user ID from the database.
	 *
	 * This function deletes refresh tokens associated with a specific user ID from the database.
	 *
	 * @function DeleteRefreshTokenWithUserID
	 * @param {number} userID - The ID of the user whose refresh tokens should be deleted.
	 * @returns {Promise<Object>} A promise that resolves to the result of the deletion operation.
	 */
	DeleteRefreshTokenWithUserID(userID) {
		const QUERY = `
			DELETE FROM 
				authorization_tokens 
			WHERE user_id = ?`;

		return new Promise((resolve, reject) => {
			mysql.query(QUERY, [userID], (err, result) => {
				if (err) {
					reject(err);
				}

				resolve(result);
			});
		});
	}

	/**
	 * Logs out a user by deleting the associated access token from the database.
	 *
	 * This function deletes the access token associated with a specific user ID from the database,
	 * effectively logging out the user.
	 *
	 * @function Logout
	 * @param {number} userID - The ID of the user to log out.
	 * @param {string} accessToken - The access token to delete.
	 * @returns {Promise<Object>} A promise that resolves to the result of the logout operation.
	 */
	Logout(userID, accessToken) {
		const QUERY = `
			DELETE FROM 
				authorization_tokens 
			WHERE user_id = ? 
				AND access_token = ?`;

		return new Promise((resolve, reject) => {
			mysql.query(QUERY, [userID, accessToken], (err, result) => {
				if (err) {
					reject(err);
				}

				resolve(result);
			});
		});
	}

	/**
	 * Saves authorization information to the database.
	 *
	 * This function inserts authorization information, including access token, refresh token,
	 * and user ID, into the authorization_tokens table in the database.
	 *
	 * @function SaveAuthorizationInfo
	 * @param {Object} data - An object containing the authorization information.
	 * @param {string} data.access_token - The access token to be saved.
	 * @param {string} data.refresh_token - The refresh token to be saved.
	 * @param {number} data.user_id - The ID of the user associated with the tokens.
	 * @param {Object} connection - The database connection object.
	 * @returns {Promise<Object>} A promise that resolves to the result of the save operation.
	 */
	SaveAuthorizationInfo({ access_token, refresh_token, user_id }, connection) {
		const QUERY = `
			INSERT INTO 
				authorization_tokens 
			(user_id, access_token, refresh_token) 
				VALUES(?,?,?)
		`;

		return new Promise((resolve, reject) => {
			connection.query(
				QUERY,
				[user_id, access_token, refresh_token],
				(err, result) => {
					if (err) {
						reject(err);
					}
					resolve(result);
				}
			);
		});
	}

	/**
	 * Updates authorization information in the database.
	 *
	 * This function updates the access token and refresh token for a specific user in the
	 * authorization_tokens table based on the provided user ID and previous refresh token.
	 *
	 * @function UpdateAuthorizationInfo
	 * @param {Object} data - An object containing the updated authorization information.
	 * @param {number} data.user_id - The ID of the user whose authorization information is being updated.
	 * @param {string} data.new_access_token - The new access token to be updated.
	 * @param {string} data.new_refresh_token - The new refresh token to be updated.
	 * @param {string} data.prev_refresh_token - The previous refresh token used to verify the update operation.
	 * @returns {Promise<Object>} A promise that resolves to the result of the update operation.
	 */
	UpdateAuthorizationInfo({
		user_id,
		new_access_token,
		new_refresh_token,
		prev_refresh_token,
	}) {
		return new Promise((resolve, reject) => {
			const QUERY = `
				UPDATE 
					authorization_tokens 
				SET 
					access_token = ?, 
					refresh_token = ?, 
					date_modified = NOW() 
				WHERE 
					user_id = ? AND refresh_token = ?
			`;

			mysql.query(
				QUERY,
				[new_access_token, new_refresh_token, user_id, prev_refresh_token],
				(err, result) => {
					if (err) {
						reject(err);
					}

					resolve(result);
				}
			);
		});
	}

	/**
	 * Sends a One-Time Password (OTP) to the user's email for password recovery.
	 *
	 * This function initiates the process of sending an OTP to the user's email address
	 * for password recovery. It calls a stored procedure to verify the user's email, OTP,
	 * and token details.
	 *
	 * @function SendOTP
	 * @param {Object} data - An object containing the OTP and token information.
	 * @param {string} data.email - The user's email address to send the OTP.
	 * @param {string} data.otp - The One-Time Password (OTP) for password recovery.
	 * @param {string} data.token - The token associated with the password recovery process.
	 * @param {Date} data.token_expiration - The expiration date and time of the token.
	 * @returns {Promise<Object>} A promise that resolves to the result of the OTP sending operation.
	 */
	SendOTP({ email, otp, token, token_expiration }) {
		const QUERY = `call WEB_USER_CHECK_USER_FORGOT_PASSWORD_PROFILES(?,?,?,?)`;

		return new Promise((resolve, reject) => {
			mysql.query(
				QUERY,
				[email, otp, token, token_expiration],
				(err, result) => {
					if (err) {
						reject(err);
					}

					resolve(result);
				}
			);
		});
	}

	/**
	 * Verifies the One-Time Password (OTP) provided by the user for password recovery.
	 *
	 * This function verifies the OTP provided by the user during the password recovery process.
	 * It calls a stored procedure to validate the OTP against the user's ID.
	 *
	 * @function VerifyOTP
	 * @param {Object} data - An object containing the user ID and OTP information.
	 * @param {string} data.user_id - The ID of the user requesting password recovery.
	 * @param {string} data.otp - The One-Time Password (OTP) provided by the user.
	 * @returns {Promise<Object>} A promise that resolves to the result of the OTP verification operation.
	 */
	VerifyOTP({ user_id, otp }) {
		const QUERY = `call WEB_USER_CHECK_OTP(?,?)`;

		return new Promise((resolve, reject) => {
			mysql.query(QUERY, [user_id, otp], (err, result) => {
				if (err) {
					reject(err);
				}

				resolve(result);
			});
		});
	}

	/**
	 * Changes the password for a user.
	 *
	 * This function updates the password for a user identified by their user ID.
	 * It calls a stored procedure to change the user's password.
	 *
	 * @function ChangePassword
	 * @param {Object} data - An object containing the new password and user ID.
	 * @param {string} data.password - The new password for the user.
	 * @param {string} data.user_id - The ID of the user whose password is to be changed.
	 * @returns {Promise<Object>} A promise that resolves to the result of the password change operation.
	 */
	ChangePassword({ password, user_id }) {
		const QUERY = `call WEB_USER_CHANGE_PASSWORD(?,?)`;

		return new Promise((resolve, reject) => {
			mysql.query(QUERY, [user_id, password], (err, result) => {
				if (err) {
					reject(err);
				}
				resolve(result);
			});
		});
	}

	/**
	 * Changes the old password for a user.
	 *
	 * This function updates the old password for a user identified by their user ID.
	 * It calls a stored procedure to change the user's old password to a new one.
	 *
	 * @function ChangeOldPassword
	 * @param {Object} data - An object containing the user ID, old password, new password, and confirm password.
	 * @param {string} data.user_id - The ID of the user whose old password is to be changed.
	 * @param {string} data.old_password - The old password of the user.
	 * @param {string} data.new_password - The new password to be set for the user.
	 * @param {string} data.confirm_password - The confirmation of the new password.
	 * @returns {Promise<Object>} A promise that resolves to the result of the old password change operation.
	 */
	ChangeOldPassword({ user_id, old_password, new_password, confirm_password }) {
		const QUERY = `call WEB_USER_CHANGE_OLD_PASSWORD(?,?,?,?)`;

		return new Promise((resolve, reject) => {
			mysql.query(
				QUERY,
				[user_id, old_password, new_password, confirm_password],
				(err, result) => {
					if (err) {
						reject(err);
					}

					resolve(result);
				}
			);
		});
	}

	/**
	 * Retrieves details of a user.
	 *
	 * This function retrieves various details of a user identified by their user ID.
	 * It fetches information such as user ID, username, role, name, email, address,
	 * mobile number, RFID card tag, and balance associated with the user.
	 *
	 * @function GetUserDetails
	 * @param {string} userID - The ID of the user whose details are to be retrieved.
	 * @returns {Promise<Object>} A promise that resolves to the details of the user.
	 */
	GetUserDetails(userID) {
		const QUERY = `
			SELECT 
				u.id AS user_id,
				ud.id AS user_driver_id,
				u.username,
				u.role,
				ud.name,
				ud.email,
				ud.address,
				ud.mobile_number,
				rc.rfid_card_tag,
				rc.balance
			FROM users AS u
			INNER JOIN user_drivers AS ud ON u.id = ud.user_id
			INNER JOIN rfid_cards AS rc ON ud.id = rc.user_driver_id
			WHERE u.id = ?`;

		return new Promise((resolve, reject) => {
			mysql.query(QUERY, [userID], (err, result) => {
				if (err) {
					reject(err);
				}

				resolve(result);
			});
		});
	}

	/**
	 * Retrieves the role of a user by their ID.
	 *
	 * This function retrieves the role of a user identified by their user ID.
	 * It fetches the role associated with the user from the database.
	 *
	 * @function GetUserRoleByID
	 * @param {string} userID - The ID of the user whose role is to be retrieved.
	 * @returns {Promise<Object>} A promise that resolves to the role of the user.
	 */
	GetUserRoleByID(userID) {
		const QUERY = `
			SELECT
				role
			FROM 
				users
			WHERE 
				id = ?
		`;

		return new Promise((resolve, reject) => {
			mysql.query(QUERY, [userID], (err, result) => {
				if (err) {
					reject(err);
				}

				resolve(result);
			});
		});
	}

	UpdateLastActiveAccount(userID, connection) {
		const QUERY = `
			UPDATE
				users
			SET
				user_status = 'ACTIVE',
				date_modified = NOW()
			WHERE 
				id = ?
		`;

		return new Promise((resolve, reject) => {
			if (connection) {
				connection.query(QUERY, [userID], (err, result) => {
					if (err) reject(err);

					resolve(result);
				});
			} else {
				mysql.query(QUERY, [userID], (err, result) => {
					if (err) reject(err);

					resolve(result);
				});
			}
		});
	}

	/**
	 * Records an audit trail of administrative actions.
	 *
	 * This function logs administrative actions into the admin_audit_trails table in the database.
	 * It records details such as the administrator ID, the ID of the associated CPO (Charging Point Operator),
	 * the action performed, and any additional remarks.
	 *
	 * @function AuditTrail
	 * @param {string} admin_id - The ID of the administrator performing the action.
	 * @param {string} cpo_id - The ID of the Charging Point Operator associated with the action.
	 * @param {string} action - The action performed by the administrator.
	 * @param {string} remarks - Additional remarks or details about the action.
	 * @returns {Promise<Object>} A promise that resolves to the result of the database operation.
	 */
	AuditTrail({ admin_id, cpo_id, action, remarks }) {
		const QUERY = `
			INSERT INTO 
				admin_audit_trails (admin_id, cpo_id, action, remarks, date_created, date_modified)
			VALUES (
				?,?,?,?,NOW(),NOW()
			)
		`;

		return new Promise((resolve, reject) => {
			mysql.query(QUERY, [admin_id, cpo_id, action, remarks], (err, result) => {
				if (err) {
					reject(err);
				}

				resolve(result);
			});
		});
	}
};
