const Crypto = require("../utils/Crypto");
const { HttpUnauthorized } = require("../utils/HttpError");
const crypto = require("crypto");

jest.mock("crypto", () => {
	return {
		createCipheriv: () => ({
			update: jest.fn().mockReturnValue("encrypted"),
			final: jest.fn().mockReturnValue("final"),
		}),
		createDecipheriv: () => ({
			update: jest.fn().mockReturnValue("encrypted"),
			final: jest.fn().mockReturnValue("final"),
		}),
		randomBytes: jest.fn(),
	};
});

describe("Crypto class - Unit Tests", () => {
	beforeEach(() => {});

	afterEach(() => {
		jest.clearAllMocks();
	});

	it("should successfully Encrypt", () => {
		const result = Crypto.Encrypt("hello");

		expect(result).toBe("encryptedfinal");
	});

	it("should successfully Decrypt", () => {
		const result = Crypto.Decrypt("hello");

		expect(result).toBe("encryptedfinal");
	});

	it("should successfully Decrypt", () => {
		const result = Crypto.Decrypt("hello");

		expect(result).toBe("encryptedfinal");
	});

	it("should throw Unauthorized", () => {
		const createDecipherivSpy = jest
			.spyOn(crypto, "createDecipheriv")
			.mockImplementation(() => ({
				update: jest.fn().mockImplementation(() => {
					throw new Error("Error");
				}),
				final: jest.fn().mockReturnValue("custom final data"),
			}));

		try {
			Crypto.Decrypt("hello");
		} catch (err) {
			expect(err).toBeInstanceOf(HttpUnauthorized);
			expect(err.message).toBe("Invalid Token");
		}

		createDecipherivSpy.mockRestore();
	});

	it("should generate random bytes", () => {
		const createDecipherivSpy = jest
			.spyOn(crypto, "randomBytes")
			.mockReturnValue("random-bytes");

		const result = Crypto.Generate();

		expect(result).toEqual({ key: "random-bytes", iv: "random-bytes" });
	});
});
