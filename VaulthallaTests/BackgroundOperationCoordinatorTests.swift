import Testing
import Foundation
@testable import Vaulthalla

/// AUDIT #12 — the background operation coordinator is the app's FIFO queue
/// for long-running work (imports, previews, compaction). These tests prove
/// the queue semantics the production flow depends on:
///  - submissions are never lost or reordered (strict FIFO, serialized);
///  - every submission still requests background lifetime extension;
///  - cancellation is acknowledged by the active (cooperative) operation,
///    drops queued work, and leaves the coordinator idle;
///  - the coordinator accepts new work after a cancel/drain cycle.
@MainActor
struct BackgroundOperationCoordinatorTests {

    private final class RequestRecorder: @unchecked Sendable {
        private let lock = NSLock()
        private var _count = 0
        var count: Int { lock.lock(); defer { lock.unlock() }; return _count }
        func record() { lock.lock(); _count += 1; lock.unlock() }
    }

    private final class Flag: @unchecked Sendable {
        private let lock = NSLock()
        private var _value = false
        var value: Bool {
            get { lock.lock(); defer { lock.unlock() }; return _value }
            set { lock.lock(); _value = newValue; lock.unlock() }
        }
    }

    private func makeCoordinator(recording: Bool = true) -> (BackgroundOperationCoordinator, RequestRecorder) {
        let coordinator = BackgroundOperationCoordinator()
        let recorder = RequestRecorder()
        // Never touch the real BGTaskScheduler from tests.
        coordinator.requestSubmitter = { [recorder] _ in
            if recording { recorder.record() }
        }
        return (coordinator, recorder)
    }

    private func waitUntil(_ flag: Flag, _ expected: Bool) async {
        let deadline = Date().addingTimeInterval(10)
        while flag.value != expected && Date() < deadline {
            try? await Task.sleep(for: .milliseconds(5))
        }
    }

    /// An operation that records its id, then blocks until cancelled.
    private func blockingOperation(id: Int, log: OrderLog, started: Flag) -> @MainActor () async -> Bool {
        {
            started.value = true
            await log.append(id)
            while !Task.isCancelled {
                try? await Task.sleep(for: .milliseconds(5))
            }
            return false
        }
    }

    @Test func operationsRunStrictlyFIFOWithoutLoss() async {
        let (coordinator, recorder) = makeCoordinator()
        let log = OrderLog()
        coordinator.submit(title: "t", subtitle: "s") {
            await log.append(0)
            return true
        }
        coordinator.submit(title: "t", subtitle: "s") {
            await log.append(1)
            return true
        }
        coordinator.submit(title: "t", subtitle: "s") {
            await log.append(2)
            return true
        }
        await coordinator.waitUntilIdleForTests()
        #expect(await log.all() == [0, 1, 2], "operations must run in submission order")
        #expect(coordinator.isIdleForTests)
        #expect(recorder.count == 3, "every submission must request background lifetime")
    }

    @Test func operationsSerializeNotRunConcurrently() async {
        let (coordinator, _) = makeCoordinator(recording: false)
        let log = OrderLog()
        let inFlight = InFlightTracker()
        coordinator.submit(title: "t", subtitle: "s") {
            let wasConcurrent = await inFlight.enter()
            await log.append(wasConcurrent ? 100 : 0)
            try? await Task.sleep(for: .milliseconds(30))
            await inFlight.leave()
            return true
        }
        coordinator.submit(title: "t", subtitle: "s") {
            let wasConcurrent = await inFlight.enter()
            await log.append(wasConcurrent ? 101 : 1)
            try? await Task.sleep(for: .milliseconds(30))
            await inFlight.leave()
            return true
        }
        await coordinator.waitUntilIdleForTests()
        #expect(await log.all() == [0, 1], "a second operation must wait for the first")
    }

    @Test func cancellationDropsQueuedWorkAndSignalsActiveOperation() async {
        let (coordinator, _) = makeCoordinator(recording: false)
        let log = OrderLog()
        let started = Flag()
        let queuedStarted = Flag()
        coordinator.submit(title: "t", subtitle: "s", operation: blockingOperation(id: 0, log: log, started: started))
        coordinator.submit(title: "t", subtitle: "s") {
            queuedStarted.value = true
            await log.append(1)
            return true
        }
        await waitUntil(started, true)
        coordinator.cancelCurrentOperation()
        await coordinator.waitUntilIdleForTests()
        #expect(await log.all() == [0], "the active operation must acknowledge cancellation; queued work is dropped")
        #expect(!queuedStarted.value, "queued operations must not run after cancellation")
        #expect(coordinator.isIdleForTests)
    }

    @Test func coordinatorAcceptsNewWorkAfterCancelAndDrain() async {
        let (coordinator, _) = makeCoordinator(recording: false)
        let log = OrderLog()
        let started = Flag()
        coordinator.submit(title: "t", subtitle: "s", operation: blockingOperation(id: 0, log: log, started: started))
        await waitUntil(started, true)
        await coordinator.cancelAndDrain()
        #expect(coordinator.isIdleForTests, "drain must wait for the active operation to exit")
        coordinator.submit(title: "t", subtitle: "s") {
            await log.append(1)
            return true
        }
        await coordinator.waitUntilIdleForTests()
        #expect(await log.all() == [0, 1], "the coordinator must be usable after a cancel/drain cycle")
    }
}

/// Ordered, awaitable record of executed operation ids.
private actor OrderLog {
    private var values: [Int] = []
    func append(_ item: Int) { values.append(item) }
    func all() -> [Int] { values }
}

/// Tracks concurrent in-flight operations (a serialized queue must never show > 1).
private actor InFlightTracker {
    private var count = 0
    func enter() -> Bool {
        let wasConcurrent = count > 0
        count += 1
        return wasConcurrent
    }
    func leave() { count -= 1 }
}
