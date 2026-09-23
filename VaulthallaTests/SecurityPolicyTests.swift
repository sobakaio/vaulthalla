import Testing
import Foundation
import CryptoKit
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

    @Test(.serialized) @MainActor func attemptStoreAndFaceIDStateMachine() async {
        let store = AttemptStateStore.shared

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
        #expect(model.errorMessage.contains("disabled"))

        // Part 3 — a successful biometric unlock restores access.
        await store.erase()
        let successModel = VaultAppModel()
        successModel.store = VaultStore(fileManager: RedirectedFileManager(replacement: directory))
        successModel.faceIDEnabled = true
        successModel.faceIDUnlocker = ScriptedFaceIDUnlocker(results: [
            .success(SymmetricKey(size: .bits256))
        ])
        await successModel.unlockWithFaceID()
        #expect(successModel.phase == .unlocked)
        #expect(successModel.rootKey != nil)
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
