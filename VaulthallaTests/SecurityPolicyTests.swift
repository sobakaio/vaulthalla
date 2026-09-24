import Testing
import Foundation
import CryptoKit
import Security
@testable import Vaulthalla

/// Dedicated Keychain service for isolated tests. Production code and the
/// fresh-install wipe (`deleteAllVaulthallaItems`) never touch it, so a
/// model-level destruction in one test cannot race another test's items.
enum VaulthallaTestKeychain {
    static let testService = "io.sobaka.vaulthalla-tests"
}

struct SecurityPolicyTests {
    /// AUDIT #6 test isolation: unique Keychain account, temp shadow
    /// directory, and an injected device secret so a test can never touch the
    /// production attempt state or shadow file.
    private func makeIsolatedStore() throws -> (store: AttemptStateStore, directory: URL, secret: Data, account: String) {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("attempt-state-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        var secret = Data(count: 32)
        _ = secret.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }
        let account = "attempt-test-\(UUID().uuidString)"
        let store = AttemptStateStore(
            account: account,
            rootDirectory: directory,
            deviceSecret: { secret },
            service: VaulthallaTestKeychain.testService)
        return (store, directory, secret, account)
    }

    /// Writes arbitrary bytes to a Keychain item (simulates external
    /// tampering of the counter item).
    private func rawKeychainWrite(account: String, data: Data) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: VaulthallaTestKeychain.testService,
            kSecAttrAccount as String: account
        ]
        let updateAttrs: [String: Any] = [kSecValueData as String: data]
        let updated = SecItemUpdate(query as CFDictionary, updateAttrs as CFDictionary)
        if updated == errSecSuccess { return }
        guard updated == errSecItemNotFound else {
            throw AttemptStateStore.PersistenceError.keychain(updated)
        }
        var add = query
        add[kSecValueData as String] = data
        add[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        add[kSecAttrSynchronizable as String] = false
        guard SecItemAdd(add as CFDictionary, nil) == errSecSuccess else {
            throw AttemptStateStore.PersistenceError.keychain(updated)
        }
    }

    private func rawKeychainDelete(account: String) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: VaulthallaTestKeychain.testService,
            kSecAttrAccount as String: account
        ]
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw AttemptStateStore.PersistenceError.keychain(status)
        }
    }

    @Test func progressiveDelayIsBoundedAndIncreasing() {
        #expect(AttemptPolicy.delay(for: 0) == 0)
        #expect(AttemptPolicy.delay(for: 1) < AttemptPolicy.delay(for: 4))
        #expect(AttemptPolicy.delay(for: 100) <= 60)
    }

    @Test func autoDestroyRequiresExplicitConfiguration() {
        var state = AttemptState()
        state.destructivePasswordFailures = 5
        #expect(!AttemptPolicy.shouldDestroy(state: state))
        state.autoDestroyEnabled = true
        #expect(AttemptPolicy.shouldDestroy(state: state))
    }

    @Test func independentCountersDoNotCrossIncrement() {
        var state = AttemptState()
        state.pinFailures = 2
        state.faceIDFailures = 1
        state.destructivePasswordFailures = 0
        #expect(state.pinFailures == 2)
        #expect(state.faceIDFailures == 1)
        #expect(state.destructivePasswordFailures == 0)
    }

    @Test(.serialized) func checkedAttemptStatePersistsAndDoesNotDeleteBeforeUpdate() async throws {
        let (store, directory, _, _) = try makeIsolatedStore()
        defer { try? FileManager.default.removeItem(at: directory) }
        var state = AttemptState()
        state.autoDestroyEnabled = true
        state.autoDestroyThreshold = 2
        try await store.saveChecked(state)
        let first = try await store.recordFailureChecked(method: .password)
        #expect(first.destructivePasswordFailures == 1)
        let terminal = try await store.recordFailureChecked(method: .password)
        #expect(AttemptPolicy.shouldDestroy(state: terminal))
        #expect(try await store.loadChecked() == terminal)
        await #expect(throws: AttemptStateStore.PersistenceError.self) {
            try await store.recordSuccessChecked(method: .password)
        }
        #expect(try await store.loadChecked() == terminal)
    }

    @Test(.serialized) @MainActor func persistedLockoutsRejectStaleConvenienceWrappers() async throws {
        let (attempts, shadowDirectory, _, _) = try makeIsolatedStore()
        defer { try? FileManager.default.removeItem(at: shadowDirectory) }
        var state = AttemptState()
        state.pinFailures = state.pinThreshold
        state.faceIDFailures = 0
        state = try await attempts.saveChecked(state)
        await #expect(throws: AttemptStateStore.PersistenceError.self) {
            try await attempts.recordSuccessChecked(method: .pin)
        }
        await #expect(throws: AttemptStateStore.PersistenceError.self) {
            try await attempts.recordSuccessChecked(method: .faceID)
        }
        #expect(try await attempts.loadChecked() == state)
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let model = VaultAppModel()
        model.store = VaultStore(fileManager: RedirectedFileManager(replacement: directory))
        model.attemptStore = attempts
        model.phase = .locked
        model.pinEnabled = true // Simulate a stale Keychain wrapper after failed deletion.
        model.faceIDEnabled = true
        model.pendingPIN = "1234"
        await model.unlockWithPIN()
        #expect(!model.pinEnabled)
        #expect(model.pendingPIN.isEmpty)
        #expect(model.phase == .locked)
        await model.unlockWithFaceID()
        #expect(!model.faceIDEnabled)
        #expect(model.phase == .locked)
        model.pinEnabled = true
        model.faceIDEnabled = true
        await model.loadSecuritySettings()
        #expect(!model.pinEnabled && !model.faceIDEnabled)
        state.pinFailures = 0
        state.faceIDFailures = state.faceIDThreshold
        state = try await attempts.saveChecked(state)
        await #expect(throws: AttemptStateStore.PersistenceError.self) {
            try await attempts.recordSuccessChecked(method: .pin)
        }
        model.pinEnabled = true
        await model.unlockWithPIN()
        #expect(!model.pinEnabled && model.phase == .locked)
    }

    #if !targetEnvironment(simulator)
    @Test(.serialized) func existingVaultBindingStatusIsReadOnly() throws {
        let manager = FileManager.default
        let directory = try #require(manager.urls(for: .applicationSupportDirectory, in: .userDomainMask).first)
            .appendingPathComponent("Vaulthalla", isDirectory: true)
        let header = manager.fileExists(atPath: directory.appendingPathComponent("vault.header").path)
        let index = manager.fileExists(atPath: directory.appendingPathComponent("index.v1").path)
        let creation = manager.fileExists(atPath: directory.appendingPathComponent("vault.creation").path)
        let bindingStatus: String
        do {
            bindingStatus = try KeychainStore.loadDeviceSecret().count == 32 ? "present" : "invalid-length"
        } catch VaultError.keychainFailure(let status) where status == errSecItemNotFound {
            bindingStatus = "missing"
        } catch {
            bindingStatus = "unavailable"
        }
        print("Read-only physical vault state: header=\(header), index=\(index), creation=\(creation), device-binding=\(bindingStatus)")
        if header || index || creation { #expect(bindingStatus == "present") }
    }
    #endif

    @Test(.serialized) func checkedConvenienceRemovalUsesIsolatedKeychainAccount() throws {
        // ConvenienceUnlockStore lives in the production service, so the
        // fixture must too (unique account keeps it isolated from the real
        // PIN/Face ID wrappers).
        let account = "convenience-removal-test-\(UUID().uuidString)"
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: KeychainStore.defaultService,
            kSecAttrAccount as String: account
        ]
        defer { SecItemDelete(query as CFDictionary) }
        var add = query
        add[kSecValueData as String] = Data("isolated-test-record".utf8)
        add[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        #expect(SecItemAdd(add as CFDictionary, nil) == errSecSuccess)
        try ConvenienceUnlockStore.removeChecked(account: account)
        try ConvenienceUnlockStore.removeChecked(account: account) // Idempotent not-found path.
        var check = query
        check[kSecReturnAttributes as String] = true
        var result: CFTypeRef?
        #expect(SecItemCopyMatching(check as CFDictionary, &result) == errSecItemNotFound)
    }

    #if targetEnvironment(simulator)
    @Test(.serialized) func checkedConvenienceRemovalVerifiesAbsence() throws {
        try ConvenienceUnlockStore.removeAllChecked()
        #expect(!ConvenienceUnlockStore.hasPIN())
        #expect(!ConvenienceUnlockStore.hasFaceID())
    }
    #endif

    @Test(.serialized) @MainActor func attemptStoreAndFaceIDStateMachine() async throws {
        let (store, shadowDirectory, _, _) = try makeIsolatedStore()
        defer { try? FileManager.default.removeItem(at: shadowDirectory) }

        // Part 1 — counters persist across loads.
        let first = try await store.recordFailureChecked(method: .pin)
        #expect(first.pinFailures == 1)
        #expect((try await store.loadChecked()).pinFailures == 1)
        let success = try await store.recordSuccessChecked(method: .pin)
        #expect(success.pinFailures == 0)
        #expect((try await store.loadChecked()).pinFailures == 0)

        // Part 2 — Face ID failures lock out at the stored threshold (default 3).
        try await store.saveChecked(AttemptState())
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }

        let model = VaultAppModel()
        model.store = VaultStore(fileManager: RedirectedFileManager(replacement: directory))
        model.attemptStore = store
        model.phase = .locked
        model.isApplicationActive = { true }
        model.faceIDEnabled = true
        model.faceIDUnlocker = ScriptedFaceIDUnlocker(results: [
            .failure(FaceIDAuthenticationFailure()),
            .failure(FaceIDAuthenticationFailure()),
            .failure(FaceIDAuthenticationFailure())
        ])

        await model.unlockWithFaceID()
        #expect(model.faceIDEnabled)
        #expect(model.unlockStatistics.faceIDFailures == 1)
        #expect(model.phase != .unlocked)

        await model.unlockWithFaceID()
        #expect(model.faceIDEnabled)
        #expect(model.unlockStatistics.faceIDFailures == 2)

        await model.unlockWithFaceID()
        #expect(!model.faceIDEnabled)
        #expect(model.errorMessage.contains("locked out"))

        // Part 3 — a valid biometric result clears its counter, but a missing
        // vault index must not expose the unlocked UI.
        try await store.saveChecked(AttemptState())
        let successModel = VaultAppModel()
        successModel.store = VaultStore(fileManager: RedirectedFileManager(replacement: directory))
        successModel.attemptStore = store
        successModel.phase = .locked
        successModel.isApplicationActive = { true }
        successModel.faceIDEnabled = true
        successModel.faceIDUnlocker = ScriptedFaceIDUnlocker(results: [
            .success(SymmetricKey(size: .bits256))
        ])
        await successModel.unlockWithFaceID()
        #expect(successModel.phase == .locked)
        #expect(successModel.rootKey == nil)
        #expect((try await store.loadChecked()).faceIDFailures == 0)
    }

    // MARK: - AUDIT #6 — authenticated shadow (rollback / deletion detection)

    @Test(.serialized) func freshFirstUseHasNoTamperVerdict() async throws {
        let (store, directory, _, _) = try makeIsolatedStore()
        defer { try? FileManager.default.removeItem(at: directory) }
        #expect(try await store.loadChecked() == AttemptState())
    }

    @Test(.serialized) func shadowDetectsKeychainRollback() async throws {
        let (store, directory, _, account) = try makeIsolatedStore()
        defer { try? FileManager.default.removeItem(at: directory) }
        var state = AttemptState()
        state.pinFailures = 3
        try await store.saveChecked(state)
        // An external actor rewinds the counter item to a fresh install.
        try rawKeychainWrite(account: account, data: JSONEncoder().encode(AttemptState()))
        await #expect(throws: AttemptStateStore.PersistenceError.tampered) {
            _ = try await store.loadChecked()
        }
    }

    @Test(.serialized) func shadowDetectsKeychainDeletion() async throws {
        let (store, directory, _, account) = try makeIsolatedStore()
        defer { try? FileManager.default.removeItem(at: directory) }
        try await store.saveChecked(AttemptState())
        try rawKeychainDelete(account: account)
        await #expect(throws: AttemptStateStore.PersistenceError.tampered) {
            _ = try await store.loadChecked()
        }
    }

    @Test(.serialized) func corruptedShadowSealIsTampered() async throws {
        let (store, directory, _, _) = try makeIsolatedStore()
        defer { try? FileManager.default.removeItem(at: directory) }
        try await store.saveChecked(AttemptState())
        let seal = directory.appendingPathComponent("attempt-state.seal")
        var junk = try Data(contentsOf: seal)
        junk[0] ^= 0xFF
        try junk.write(to: seal)
        await #expect(throws: AttemptStateStore.PersistenceError.tampered) {
            _ = try await store.loadChecked()
        }
    }

    @Test(.serialized) func shadowLagFromCrashWindowSelfHeals() async throws {
        let (store, directory, _, account) = try makeIsolatedStore()
        defer { try? FileManager.default.removeItem(at: directory) }
        var state = AttemptState()
        state.pinFailures = 1
        state = try await store.saveChecked(state)
        // Simulate a crash between the Keychain write and the shadow write:
        // the Keychain item advances, the shadow stays behind.
        var advanced = state
        advanced.pinFailures = 2
        advanced.version = state.version + 1
        try rawKeychainWrite(account: account, data: JSONEncoder().encode(advanced))
        // The lag is a crash window, not tampering: the state is accepted and
        // the shadow is re-established.
        #expect(try await store.loadChecked() == advanced)
        let seal = directory.appendingPathComponent("attempt-state.seal")
        #expect(FileManager.default.fileExists(atPath: seal.path))
        #expect(try await store.loadChecked() == advanced)
    }

    @Test(.serialized) func shadowPersistsAcrossStoreInstances() async throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("attempt-state-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        var secret = Data(count: 32)
        _ = secret.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }
        let account = "attempt-test-\(UUID().uuidString)"
        let first = AttemptStateStore(account: account, rootDirectory: directory, deviceSecret: { secret })
        var state = AttemptState()
        state.passwordFailures = 2
        state = try await first.saveChecked(state)
        let second = AttemptStateStore(account: account, rootDirectory: directory, deviceSecret: { secret })
        #expect(try await second.loadChecked() == state)
    }
}

/// Scripted Face ID unlocker for state-machine tests (§42).
final class ScriptedFaceIDUnlocker: FaceIDUnlocking, @unchecked Sendable {
    private var queue: [Result<SymmetricKey, Error>]
    init(results: [Result<SymmetricKey, Error>]) {
        self.queue = results
    }
    func unlock() async throws -> SymmetricKey {
        guard !queue.isEmpty else { throw FaceIDUnavailableFailure() }
        let next = queue.removeFirst()
        switch next {
        case .success(let key): return key
        case .failure(let error): throw error
        }
    }
}

/// FileManager that redirects every search path to a sandboxed test directory.
final class RedirectedFileManager: FileManager {
    let replacement: URL
    init(replacement: URL) {
        self.replacement = replacement
        super.init()
    }
    required init(contentsOf fileURL: URL) throws {
        self.replacement = fileURL
        super.init()
    }
    override func urls(for directory: SearchPathDirectory, in domainMask: SearchPathDomainMask) -> [URL] {
        [replacement]
    }
}
