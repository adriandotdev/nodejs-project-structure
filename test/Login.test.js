const AccountService = require("../services/AccountService");
const { Encrypt } = require("../utils/Crypto");
const { HttpUnauthorized } = require("../utils/HttpError");
const JWT = require("../utils/JsonWebToken");

const mConnection = {
	release: jest.fn(),
	beginTransaction: jest.fn(),
	commit: jest.fn(), // Add this if you need commit in your tests
	rollback: jest.fn(),
};

jest.mock("mysql2", () => {
	const mConnection = {
		release: jest.fn(),
		beginTransaction: jest.fn(),
		commit: jest.fn(), // Add this if you need commit in your tests
		rollback: jest.fn(),
	};
	const mPool = {
		getConnection: jest.fn((callback) => callback(null, mConnection)),
		on: jest.fn(),
	};
	return {
		createPool: jest.fn(() => mPool),
	};
});

jest.mock("../utils/JsonWebToken.js", () => {
	return {
		Sign: jest.fn(),
	};
});

jest.mock("../utils/Crypto.js", () => {
	return {
		Encrypt: jest.fn(),
		Decrypt: jest.fn(),
	};
});

const mockRepository = {
	GetConnection: jest.fn().mockResolvedValue(mConnection),
	Login: jest
		.fn()
		.mockResolvedValue([
			{ id: 1, role: "USER_DRIVER", rfid_card_tag: "12345678" },
		]),
	GetUserPrivileges: jest.fn().mockResolvedValue([{ user_id: undefined }]),
	SaveAuthorizationInfo: jest.fn().mockResolvedValue(1),
	GetUserDetails: jest.fn(),
	UpdateLastActiveAccount: jest.fn().mockResolvedValue(1),
	AuditTrail: jest.fn(),
};

describe("Login Unit Tests", () => {
	/**
	 * @type {AccountService}
	 */
	let service;

	beforeEach(() => {
		service = new AccountService(mockRepository);
	});

	afterEach(() => {
		jest.clearAllMocks();
	});

	it("should successfully login - USER DRIVER", async () => {
		const result = await service.Login({
			username: "username",
			password: "password",
		});

		expect(result).toBeTruthy();
		expect(JWT.Sign).toHaveBeenCalledTimes(2);
		expect(Encrypt).toHaveBeenCalledTimes(2);
		expect(mockRepository.SaveAuthorizationInfo).toHaveBeenCalledTimes(1);
		expect(mockRepository.AuditTrail).toHaveBeenCalledTimes(0);
	});

	it("should successfully login - ADMIN NOC", async () => {
		mockRepository.Login = jest.fn().mockResolvedValue([
			{
				id: 1,
				role: "ADMIN_NOC",
			},
		]);

		mockRepository.GetUserPrivileges.mockResolvedValueOnce([{ user_id: 1 }]);

		const result = await service.Login({
			username: "username-admin",
			password: "password",
		});

		expect(result).toBeTruthy();
		expect(mockRepository.AuditTrail).toHaveBeenCalledTimes(1);
		expect(mockRepository.AuditTrail).toHaveBeenCalledWith({
			admin_id: 1,
			cpo_id: null,
			action: `Login - User with ID of 1`,
			remarks: "success",
		});
		expect(JWT.Sign).toHaveBeenCalledTimes(2);
		expect(Encrypt).toHaveBeenCalledTimes(2);
		expect(mockRepository.SaveAuthorizationInfo).toHaveBeenCalledTimes(1);
	});

	it("should successfully login - CPO OWNER", async () => {
		mockRepository.Login = jest.fn().mockResolvedValue([
			{
				id: 1,
				role: "CPO_OWNER",
			},
		]);

		const result = await service.Login({
			username: "username-admin",
			password: "password",
		});

		expect(result).toBeTruthy();
		expect(mockRepository.AuditTrail).toHaveBeenCalledTimes(1);
		expect(mockRepository.AuditTrail).toHaveBeenCalledWith({
			admin_id: null,
			cpo_id: 1,
			action: `Login - User with ID of 1`,
			remarks: "success",
		});
		expect(JWT.Sign).toHaveBeenCalledTimes(2);
		expect(Encrypt).toHaveBeenCalledTimes(2);
		expect(mockRepository.SaveAuthorizationInfo).toHaveBeenCalledTimes(1);
	});

	it("should return Unauthorized when username or password is incorrect", async () => {
		mockRepository.Login = jest.fn().mockResolvedValue([]);

		try {
			await service.Login({
				username: "username-admin",
				password: "password",
			});
		} catch (err) {
			expect(err).toBeInstanceOf(HttpUnauthorized);
			expect(err.message).toBe("Unauthorized");
		}
	});

	it("should return Unauthorized when account status is INACTIVE", async () => {
		mockRepository.Login = jest
			.fn()
			.mockResolvedValue([
				{ id: 1, role: "USER_DRIVER", user_status: "INACTIVE" },
			]);

		try {
			await service.Login({
				username: "username-admin",
				password: "password",
			});
		} catch (err) {
			expect(err).toBeInstanceOf(HttpUnauthorized);
			expect(err.message).toBe("ACCOUNT_IS_DEACTIVATED");
		}
	});
});
