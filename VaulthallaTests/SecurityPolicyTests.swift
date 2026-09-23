import Testing
import Foundation
import CryptoKit
import Security
@testable import Vaulthalla

struct SecurityPolicyTests {
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
        let store = AttemptStateStore(account: "attempt-test-\(UUID().uuidString)")
        await store.erase()
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
        await store.erase()
    }

    @Test(.serialized) @MainActor func persistedLockoutsRejectStaleConvenienceWrappers() async throws {
        let attempts = AttemptStateStore(account: "lockout-test-\(UUID().uuidString)")
        var state = AttemptState()
        state.pinFailures = state.pinThreshold
        state.faceIDFailures = 0
        try await attempts.saveChecked(state)
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
        try await attempts.saveChecked(state)
        await #expect(throws: AttemptStateStore.PersistenceError.self) {
            try await attempts.recordSuccessChecked(method: .pin)
        }
        model.pinEnabled = true
        await model.unlockWithPIN()
        #expect(!model.pinEnabled && model.phase == .locked)
        await attempts.erase()
    }

    @Test(.serialized) func checkedConvenienceRemovalUsesIsolatedKeychainAccount() throws {
        let account = "convenience-removal-test-\(UUID().uuidString)"
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "io.sobaka.vaulthalla",
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

    @Test(.serialized) @MainActor func attemptStoreAndFaceIDStateMachine() async {
        let store = AttemptStateStore(account: "attempt-test-\(UUID().uuidString)")

        // Part 1 — counters persist across loads.
        await store.erase()
        let first = await store.recordFailure(method: .pin)
        #expect(first.pinFailures == 1)
        #expect((await store.load()).pinFailures == 1)
        let success = await store.recordSuccess(method: .pin)
        #expect(success.pinFailures == 0)
        #expect((await store.load()).pinFailures == 0)

        // Part 2 — Face ID failures lock out at the stored threshold (default 3).
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        try? FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }

        await store.erase()
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
        await store.erase()
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
        #expect((await store.load()).faceIDFailures == 0)

        await store.erase()
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
