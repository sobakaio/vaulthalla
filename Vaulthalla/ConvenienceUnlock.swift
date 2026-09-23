import Foundation
import CryptoKit
import Security
import LocalAuthentication

enum ConvenienceUnlockError: Error {
    case unavailable
    case invalidPIN
    case notConfigured
    case invalidWrapper
}

struct PINWrapper: Codable {
    let salt: Data
    let wrappedRootKey: Data
}

enum ConvenienceUnlockStore {
    private static let service = "io.sobaka.vaulthalla"
    private static let pinAccount = "pin-wrapper-v1"
    private static let faceIDAccount = "faceid-wrapper-v1"

    static func configurePIN(_ pin: String, rootKey: SymmetricKey) throws {
        guard (4...8).contains(pin.count), pin.allSatisfy(\.isNumber) else {
            throw ConvenienceUnlockError.invalidPIN
        }
        let deviceSecret = try KeychainStore.loadDeviceSecret()
        let salt = VaultCrypto.randomData(count: 32)
        let pinKey = try PasswordKDF.deriveKey(password: pin, salt: salt, iterations: PasswordKDF.minimumIterations)
        let kek = VaultCrypto.makeKEK(passwordKey: pinKey, deviceSecret: deviceSecret)
        let wrapped = try VaultCrypto.wrap(rootKey, with: kek, aad: Data("Vaulthalla-PIN-v1".utf8) + salt)
        let wrapper = try JSONEncoder().encode(PINWrapper(salt: salt, wrappedRootKey: wrapped))
        try save(wrapper, account: pinAccount)
    }

    static func unlockWithPIN(_ pin: String) throws -> SymmetricKey {
        guard let data = load(account: pinAccount),
              let wrapper = try? JSONDecoder().decode(PINWrapper.self, from: data) else {
            throw ConvenienceUnlockError.notConfigured
        }
        let deviceSecret = try KeychainStore.loadDeviceSecret()
        let pinKey = try PasswordKDF.deriveKey(password: pin, salt: wrapper.salt, iterations: PasswordKDF.minimumIterations)
        let kek = VaultCrypto.makeKEK(passwordKey: pinKey, deviceSecret: deviceSecret)
        do {
            return try VaultCrypto.unwrap(wrapper.wrappedRootKey, with: kek, aad: Data("Vaulthalla-PIN-v1".utf8) + wrapper.salt)
        } catch {
            throw ConvenienceUnlockError.invalidPIN
        }
    }

    static func configureFaceID(_ rootKey: SymmetricKey) throws {
        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            .biometryCurrentSet,
            &error
        ) else {
            throw ConvenienceUnlockError.unavailable
        }
        try removeChecked(account: faceIDAccount)
        let add: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: faceIDAccount,
            kSecValueData as String: rootKey.withUnsafeBytes { Data($0) },
            kSecAttrAccessControl as String: access,
            kSecUseAuthenticationUI as String: kSecUseAuthenticationUIAllow
        ]
        guard SecItemAdd(add as CFDictionary, nil) == errSecSuccess else {
            throw ConvenienceUnlockError.unavailable
        }
    }

    static func unlockWithFaceID(using context: LAContext) throws -> SymmetricKey {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: faceIDAccount,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
            kSecUseAuthenticationUI as String: kSecUseAuthenticationUIAllow,
            kSecUseAuthenticationContext as String: context
        ]
        var result: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess,
              let data = result as? Data else {
            throw ConvenienceUnlockError.unavailable
        }
        return SymmetricKey(data: data)
    }

    static func hasPIN() -> Bool {
        load(account: pinAccount) != nil
    }

    static func hasFaceID() -> Bool {
        load(account: faceIDAccount) != nil
    }

    static func removeAllChecked() throws {
        // Attempt both removals even if the first Keychain operation fails.
        var pinFailed = false
        var faceIDFailed = false
        do { try removeChecked(account: pinAccount) } catch { pinFailed = true }
        do { try removeChecked(account: faceIDAccount) } catch { faceIDFailed = true }
        if pinFailed || faceIDFailed { throw ConvenienceUnlockError.unavailable }
    }

    static func removePINChecked() throws {
        try removeChecked(account: pinAccount)
    }

    static func removeFaceIDChecked() throws {
        try removeChecked(account: faceIDAccount)
    }

    private static func save(_ data: Data, account: String) throws {
        try removeChecked(account: account)
        let add: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            kSecAttrSynchronizable as String: false
        ]
        guard SecItemAdd(add as CFDictionary, nil) == errSecSuccess else {
            throw ConvenienceUnlockError.unavailable
        }
    }

    // Internal so tests can verify the real Keychain path with isolated accounts.
    static func removeChecked(account: String) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw ConvenienceUnlockError.unavailable
        }
        var check = query
        check[kSecReturnAttributes as String] = true
        check[kSecMatchLimit as String] = kSecMatchLimitOne
        // Never prompt for biometrics merely to verify absence.
        check[kSecUseAuthenticationUI as String] = kSecUseAuthenticationUIFail
        var result: CFTypeRef?
        guard SecItemCopyMatching(check as CFDictionary, &result) == errSecItemNotFound else {
            throw ConvenienceUnlockError.unavailable
        }
    }

    private static func load(account: String) -> Data? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        var result: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess else { return nil }
        return result as? Data
    }
}
