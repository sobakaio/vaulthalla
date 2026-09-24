import Foundation
import Network
import Observation
import CryptoKit
import Darwin
import UIKit

@MainActor
@Observable
final class LocalWebImportServer {
    enum State: Equatable {
        case stopped
        case starting
        case running
        case stopping
        case failed(String)

        var title: String {
            switch self {
            case .stopped: return "Web Import is off"
            case .starting: return "Starting Web Import…"
            case .running: return "Web Import is ready"
            case .stopping: return "Stopping Web Import…"
            case .failed: return "Web Import unavailable"
            }
        }
    }

    static let sessionDuration: TimeInterval = 15 * 60
    static let maximumUploadBytes: Int64 = 20 * 1024 * 1024 * 1024

    var state: State = .stopped
    var pairingPIN = ""
    var importURL: URL?
    /// Loopback endpoint for same-host clients (tests). `importURL` is the
    /// LAN address advertised to phones and is not always reachable from the
    /// host itself.
    var loopbackURL: URL? {
        guard case .running = state, let port = listener?.port?.rawValue else { return nil }
        return URL(string: "http://127.0.0.1:\(port)")
    }
    var activeFilename = ""
    var uploadedCount = 0
    /// Called (on the main actor) after each successfully imported file so the
    /// host UI can refresh the vault index while the import session is open.
    var onImportCompleted: (@MainActor () -> Void)?
    var lastMessage = ""
    var expiresAt: Date?

    private let store: VaultStore

    /// The shared store keeps production behavior; tests inject an isolated
    /// vault so end-to-end import tests never touch the user's vault.
    init(store: VaultStore = .shared) {
        self.store = store
    }

    private var listener: NWListener?
    /// Monotonic token so state/connection callbacks from a cancelled or
    /// replaced listener are ignored instead of corrupting the current
    /// session (rapid start/stop/start can leave stale callbacks in flight).
    private var listenerGeneration = 0
    private var token = ""
    private var failedPairings = 0
    private static let maximumPairingAttempts = 8
    private var rootKey: SymmetricKey?
    private var connections: [ObjectIdentifier: NWConnection] = [:]
    private var expiryTask: Task<Void, Never>?
    private var importTasks: [UUID: Task<MediaRecord?, Error>] = [:]
    private var importStreams: [UUID: AsyncThrowingStream<Data, Error>.Continuation] = [:]
    private var usingPreferredPort = false
    private var previousIdleTimerState: Bool?

    func start(rootKey: SymmetricKey) {
        // Plain HTTP exposes the PIN, token and media to an active LAN
        // attacker. A secure transport is still pending; the UI warns the
        // user until one is implemented.
        stop()
        previousIdleTimerState = UIApplication.shared.isIdleTimerDisabled
        UIApplication.shared.isIdleTimerDisabled = true
        self.rootKey = rootKey
        token = Self.makeToken()
        pairingPIN = String(format: "%08d", Int.random(in: 0..<100_000_000))
        failedPairings = 0
        state = .starting
        uploadedCount = 0
        activeFilename = ""
        lastMessage = ""
        expiresAt = Date().addingTimeInterval(Self.sessionDuration)

        do {
            usingPreferredPort = true
            listenerGeneration &+= 1
            try installListener(on: NWEndpoint.Port(rawValue: 80) ?? .any, generation: listenerGeneration)
            expiryTask = Task { @MainActor [weak self] in
                try? await Task.sleep(for: .seconds(Self.sessionDuration))
                guard !Task.isCancelled else { return }
                self?.stop()
            }
        } catch {
            UIApplication.shared.isIdleTimerDisabled = previousIdleTimerState ?? false
            previousIdleTimerState = nil
            state = .failed("Could not start the local server.")
            self.rootKey = nil
            token = ""
            pairingPIN = ""
        }
    }

    private func installListener(on port: NWEndpoint.Port, generation: Int) throws {
        let listener = try NWListener(using: .tcp, on: port)
        listener.newConnectionHandler = { [weak self] connection in
            Task { @MainActor [weak self] in
                // A stale listener (already cancelled/replaced) must never
                // feed connections into the current session.
                guard let self, generation == self.listenerGeneration else {
                    connection.cancel()
                    return
                }
                self.accept(connection)
            }
        }
        listener.stateUpdateHandler = { [weak self] listenerState in
            Task { @MainActor [weak self] in
                guard let self, generation == self.listenerGeneration else { return }
                self.handle(listenerState)
            }
        }
        self.listener = listener
        listener.start(queue: DispatchQueue(label: "io.sobaka.vaulthalla.web-import"))
    }

    func stop() {
        if let previousIdleTimerState {
            UIApplication.shared.isIdleTimerDisabled = previousIdleTimerState
            self.previousIdleTimerState = nil
        }
        guard state != .stopped || listener != nil else { return }
        state = .stopping
        expiryTask?.cancel()
        expiryTask = nil
        listenerGeneration &+= 1
        listener?.cancel()
        listener = nil
        connections.values.forEach { $0.cancel() }
        connections.removeAll()
        importStreams.values.forEach { $0.finish(throwing: CancellationError()) }
        importTasks.values.forEach { $0.cancel() }
        rootKey = nil
        token = ""
        pairingPIN = ""
        failedPairings = 0
        importURL = nil
        expiresAt = nil
        activeFilename = ""
        onImportCompleted = nil
        state = .stopped
    }

    func stopAndDrain() async {
        stop()
        let tasks = Array(importTasks.values)
        for task in tasks { _ = try? await task.value }
    }

    private func handle(_ listenerState: NWListener.State) {
        switch listenerState {
        case .ready:
            guard let port = listener?.port?.rawValue,
                  let address = Self.localIPv4Address() else {
                state = .failed("No local network address is available.")
                stop()
                return
            }
            let portSuffix = port == 80 ? "" : ":\(port)"
            importURL = URL(string: "http://\(address)\(portSuffix)")
            state = .running
        case .failed(let error):
            if usingPreferredPort {
                usingPreferredPort = false
                listener?.cancel()
                listener = nil
                listenerGeneration &+= 1
                do {
                    try installListener(on: .any, generation: listenerGeneration)
                    return
                } catch {
                    state = .failed("Could not start the local server. \(error.localizedDescription)")
                    stop()
                    return
                }
            }
            state = .failed("The local network listener stopped unexpectedly. \(error.localizedDescription)")
            stop()
        case .cancelled:
            if state != .stopped { state = .stopped }
        default:
            break
        }
    }

    private func accept(_ connection: NWConnection) {
        guard state == .running, connections.count < 4 else {
            connection.cancel()
            return
        }
        let identifier = ObjectIdentifier(connection)
        connections[identifier] = connection
        connection.stateUpdateHandler = { [weak self, weak connection] connectionState in
            guard let connection else { return }
            if case .failed = connectionState {
                Task { @MainActor [weak self] in self?.remove(connection) }
            } else if case .cancelled = connectionState {
                Task { @MainActor [weak self] in self?.remove(connection) }
            }
        }
        connection.start(queue: DispatchQueue(label: "io.sobaka.vaulthalla.web-connection"))
        receiveHeaders(from: connection, data: Data())
    }

    private func remove(_ connection: NWConnection) {
        connections.removeValue(forKey: ObjectIdentifier(connection))
    }

    private func receiveHeaders(from connection: NWConnection, data: Data) {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 64 * 1024) { [weak self] chunk, _, _, error in
            Task { @MainActor [weak self] in
                guard let self else { return }
                if error != nil {
                    self.fail(connection)
                    return
                }
                var combined = data
                if let chunk { combined.append(chunk) }
                guard combined.count <= 64 * 1024 else {
                    self.respond(connection, status: 431, body: #"{"error":"Request headers too large."}"#)
                    return
                }
                guard let separator = combined.range(of: Data([13, 10, 13, 10])) else {
                    self.receiveHeaders(from: connection, data: combined)
                    return
                }
                let headerData = combined.subdata(in: 0..<separator.lowerBound)
                let bodyPrefix = combined.subdata(in: separator.upperBound..<combined.count)
                guard let headerText = String(data: headerData, encoding: .utf8),
                      let request = self.parse(headerText) else {
                    self.respond(connection, status: 400, body: #"{"error":"Invalid HTTP request."}"#)
                    return
                }

                if request.method == "GET" {
                    self.servePage(connection, path: request.path)
                    return
                }

                if request.method == "POST", request.path == "/pair" {
                    guard request.headers["transfer-encoding"] == nil,
                          let rawLength = request.headers["content-length"],
                          let length = Int(rawLength), length == 8,
                          bodyPrefix.count <= length else {
                        self.respond(connection, status: 400, body: #"{"error":"Invalid pairing request."}"#)
                        return
                    }
                    Task { @MainActor in
                        var body = bodyPrefix
                        while body.count < length {
                            guard let next = await self.receiveNext(connection), !next.isEmpty,
                                  body.count + next.count <= length else {
                                self.fail(connection)
                                return
                            }
                            body.append(next)
                        }
                        guard self.failedPairings < Self.maximumPairingAttempts else {
                            self.respond(connection, status: 429, body: #"{"error":"Too many attempts. Restart Web Import for a new PIN."}"#)
                            return
                        }
                        guard let candidate = String(data: body, encoding: .ascii),
                              candidate.count == 8, candidate.allSatisfy(\.isNumber),
                              candidate == self.pairingPIN else {
                            self.failedPairings += 1
                            self.respond(connection, status: 403, body: #"{"error":"Wrong PIN. Check the iPhone screen."}"#)
                            return
                        }
                        self.respond(connection, status: 200, body: WebImportPage.html(token: self.token), contentType: "text/html; charset=utf-8")
                    }
                    return
                }

                guard request.method == "POST",
                      request.path == "/import/\(self.token)/upload",
                      request.headers["transfer-encoding"] == nil,
                      let lengthString = request.headers["content-length"],
                      let length = Int64(lengthString),
                      length >= 0,
                      length <= Self.maximumUploadBytes else {
                    self.respond(connection, status: 400, body: #"{"error":"Only bounded authenticated uploads are accepted."}"#)
                    return
                }

                let filename = Self.sanitizeFilename(request.headers["x-filename"] ?? "upload")
                let mimeType = Self.sanitizeMimeType(request.headers["x-mime-type"] ?? "application/octet-stream")
                self.receiveBody(from: connection, prefix: bodyPrefix, expectedLength: length, filename: filename, mimeType: mimeType)
            }
        }
    }

    private func receiveBody(
        from connection: NWConnection,
        prefix: Data,
        expectedLength: Int64,
        filename: String,
        mimeType: String
    ) {
        guard let importRootKey = rootKey else {
            respond(connection, status: 423, body: #"{"error":"Vault is locked."}"#)
            return
        }

        let (stream, continuation) = AsyncThrowingStream<Data, Error>.makeStream()
        let importID = UUID()
        let importTask = Task {
            try await store.importStream(stream, filename: filename, mimeType: mimeType, rootKey: importRootKey)
        }
        importTasks[importID] = importTask
        importStreams[importID] = continuation

        Task { @MainActor [weak self] in
            guard let self else { return }
            defer {
                self.importTasks.removeValue(forKey: importID)
                self.importStreams.removeValue(forKey: importID)
            }
            guard self.state == .running else {
                continuation.finish(throwing: CancellationError())
                importTask.cancel()
                _ = try? await importTask.value
                return
            }
            self.activeFilename = filename
            var received = Int64(0)
            let initial = Data(prefix.prefix(Int(min(Int64(prefix.count), expectedLength))))
            if !initial.isEmpty {
                continuation.yield(initial)
                received = Int64(initial.count)
            }

            while received < expectedLength, self.state == .running {
                guard let chunk = await self.receiveNext(connection), !chunk.isEmpty else {
                    continuation.finish(throwing: VaultError.storageFailure)
                    let response = await self.waitForImport(importTask)
                    self.respond(connection, status: response.status, body: response.body)
                    return
                }
                let remaining = expectedLength - received
                let accepted = Data(chunk.prefix(Int(min(Int64(chunk.count), remaining))))
                continuation.yield(accepted)
                received += Int64(accepted.count)
            }

            if received == expectedLength {
                continuation.finish()
            } else {
                continuation.finish(throwing: CancellationError())
            }

            let response = await self.waitForImport(importTask)
            self.activeFilename = ""
            if response.status == 201 {
                self.uploadedCount += 1
                self.onImportCompleted?()
            }
            self.lastMessage = response.status == 201 ? "Imported (filename)." : response.status == 200 ? "Duplicate skipped." : "Import failed."
            self.respond(connection, status: response.status, body: response.body)
        }
    }

    private func receiveNext(_ connection: NWConnection) async -> Data? {
        await withCheckedContinuation { continuation in
            connection.receive(minimumIncompleteLength: 1, maximumLength: 256 * 1024) { data, _, _, _ in
                continuation.resume(returning: data)
            }
        }
    }

    private func waitForImport(_ task: Task<MediaRecord?, Error>) async -> (status: Int, body: String) {
        do {
            let record = try await task.value
            return record == nil ? (200, #"{"ok":true,"duplicate":true}"#) : (201, #"{"ok":true,"duplicate":false}"#)
        } catch is CancellationError {
            return (499, #"{"error":"Upload cancelled."}"#)
            } catch let error as LocalizedError {
                let message = error.errorDescription ?? "Encrypted import failed."
                let escaped = message.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"")
                return (422, "{\"error\":\"\(escaped)\"}")
            } catch {
                return (500, #"{"error":"Encrypted import failed."}"#)
        }
    }

    private func servePage(_ connection: NWConnection, path: String) {
        guard path == "/" else {
            respond(connection, status: 404, body: #"{"error":"Not found."}"#)
            return
        }
        respond(connection, status: 200, body: WebImportPage.pairingHTML, contentType: "text/html; charset=utf-8")
    }

    private func respond(_ connection: NWConnection, status: Int, body: String, contentType: String = "application/json; charset=utf-8") {
        let reason = status == 200 ? "OK" : status == 201 ? "Created" : status == 400 ? "Bad Request" : status == 403 ? "Forbidden" : status == 429 ? "Too Many Requests" : status == 404 ? "Not Found" : status == 422 ? "Unprocessable Content" : status == 423 ? "Locked" : status == 431 ? "Request Header Fields Too Large" : status == 499 ? "Client Closed Request" : "Internal Server Error"
        let bodyData = Data(body.utf8)
        let header = "HTTP/1.1 \(status) \(reason)\r\nContent-Type: \(contentType)\r\nContent-Length: \(bodyData.count)\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nContent-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'\r\nConnection: close\r\n\r\n"
        connection.send(content: Data(header.utf8) + bodyData, completion: .contentProcessed { [weak self] _ in
            Task { @MainActor [weak self] in
                self?.remove(connection)
                connection.cancel()
            }
        })
    }

    private func fail(_ connection: NWConnection) {
        connection.cancel()
        remove(connection)
    }

    private struct HTTPRequest {
        let method: String
        let path: String
        let headers: [String: String]
    }

    private func parse(_ text: String) -> HTTPRequest? {
        let lines = text.components(separatedBy: "\r\n")
        guard let requestLine = lines.first else { return nil }
        let parts = requestLine.split(separator: " ", maxSplits: 2).map(String.init)
        guard parts.count == 3 else { return nil }
        var headers: [String: String] = [:]
        for line in lines.dropFirst() {
            guard !line.isEmpty, let separator = line.firstIndex(of: ":") else { continue }
            let name = line[..<separator].lowercased()
            let value = line[line.index(after: separator)...].trimmingCharacters(in: .whitespaces)
            headers[name] = value
        }
        return HTTPRequest(method: parts[0].uppercased(), path: parts[1], headers: headers)
    }

    private static func makeToken() -> String {
        Data((0..<24).map { _ in UInt8.random(in: 0...255) }).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    private static func sanitizeFilename(_ value: String) -> String {
        let decoded = value.removingPercentEncoding ?? value
        let base = URL(fileURLWithPath: decoded).lastPathComponent.replacingOccurrences(of: "\\", with: "_").trimmingCharacters(in: .whitespacesAndNewlines)
        return String((base.isEmpty ? "upload" : base).prefix(180))
    }

    private static func sanitizeMimeType(_ value: String) -> String {
        let allowed = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-./+")
        let filtered = String(value.unicodeScalars.filter { allowed.contains($0) })
        return filtered.isEmpty ? "application/octet-stream" : String(filtered.prefix(120))
    }

    private static func localIPv4Address() -> String? {
        var interfaces: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&interfaces) == 0, let first = interfaces else { return nil }
        defer { freeifaddrs(interfaces) }
        var candidates: [(name: String, address: String)] = []
        for pointer in sequence(first: first, next: { $0.pointee.ifa_next }) {
            let interface = pointer.pointee
            guard let name = interface.ifa_name,
                  interface.ifa_addr?.pointee.sa_family == UInt8(AF_INET),
                  let sockaddr = interface.ifa_addr else { continue }
            let interfaceName = String(cString: name)
            guard interfaceName != "lo0",
                  !interfaceName.hasPrefix("utun"),
                  !interfaceName.hasPrefix("pdp_ip"),
                  !interfaceName.hasPrefix("bridge"),
                  !interfaceName.hasPrefix("awdl"),
                  !interfaceName.hasPrefix("llw") else { continue }
            var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            getnameinfo(sockaddr, socklen_t(sockaddr.pointee.sa_len), &host, socklen_t(host.count), nil, 0, NI_NUMERICHOST)
            let value = String(cString: host)
            guard value.hasPrefix("192.168.") || value.hasPrefix("10.") || value.hasPrefix("172.") else { continue }
            candidates.append((interfaceName, value))
        }
        return candidates.first(where: { $0.name == "en0" || $0.name == "en1" })?.address ?? candidates.first?.address
    }
}

enum WebImportPage {
    static let pairingHTML = """
    <!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
    <title>Vaulthalla pairing</title><style>body{font:16px -apple-system,sans-serif;max-width:380px;margin:15vh auto;padding:24px;color:#eee;background:#111}input,button{box-sizing:border-box;width:100%;padding:14px;font:inherit;margin:8px 0;border-radius:10px}input{background:#222;color:white;border:1px solid #666}button{background:#2997ff;color:white;border:0}p{line-height:1.5}</style>
    <h1>Pair with Vaulthalla</h1><p>Enter the 8-digit PIN shown on your iPhone. Only pair on a Wi-Fi network you trust.</p>
    <form id="pair"><input id="pin" type="text" inputmode="numeric" pattern="[0-9]{8}" maxlength="8" autocomplete="off" required placeholder="8-digit PIN"><button>Pair</button></form><p id="status"></p>
    <script>document.getElementById('pair').onsubmit=async e=>{e.preventDefault();const status=document.getElementById('status');try{const r=await fetch('/pair',{method:'POST',body:document.getElementById('pin').value,headers:{'Content-Type':'text/plain'}});const text=await r.text();if(r.ok){document.open();document.write(text);document.close()}else{status.textContent=JSON.parse(text).error||'Pairing failed'}}catch{status.textContent='Connection lost'}}</script>
    </html>
    """
    static func html(token: String) -> String {
        let endpoint = "/import/\(token)/upload"
        return """
        <!doctype html>
        <html lang="en">
        <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
        <meta name="color-scheme" content="light dark">
        <title>Vaulthalla</title>
        <style>
        :root{color-scheme:light dark;--bg:#ffffff;--text:#1d1d1f;--muted:#86868b;--accent:#0071e3;--border:#d2d2d7;--card:#ffffff;--track:#e8e8ed;--fill:#0071e3}
        @media(prefers-color-scheme:dark){:root{--bg:#000000;--text:#f5f5f7;--muted:#86868b;--accent:#2997ff;--border:#38383a;--card:#1c1c1e;--track:#38383a;--fill:#2997ff}}
        *{box-sizing:border-box;margin:0}
        html,body{min-height:100%}
        body{font-family:-apple-system,BlinkMacSystemFont,"SF Pro Text","Helvetica Neue",Helvetica,Arial,sans-serif;background:var(--bg);color:var(--text);-webkit-font-smoothing:antialiased}
        .wrap{min-height:100vh;display:flex;align-items:center;justify-content:center;padding:48px 20px}
        main{width:100%;max-width:400px;text-align:center}
        .wordmark{display:flex;align-items:center;justify-content:center;gap:9px;margin-bottom:34px}
        .wordmark svg{width:22px;height:22px;display:block}
        .wordmark span{font-size:22px;font-weight:600;letter-spacing:-.02em}
        .card{border:1px solid var(--border);border-radius:20px;background:var(--card);padding:30px 26px 26px;text-align:left}
        .drop{display:flex;flex-direction:column;align-items:center;gap:13px;border:1.5px dashed var(--border);border-radius:16px;padding:42px 20px 36px;cursor:pointer;text-align:center;transition:border-color .15s ease,background-color .15s ease;-webkit-tap-highlight-color:transparent}
        .drop:hover{border-color:var(--accent)}
        .drop.over{border-color:var(--accent);background:rgba(0,113,227,.06)}
        .drop svg{width:46px;height:46px;display:block}
        .drop strong{font-size:17px;font-weight:600;letter-spacing:-.01em}
        .drop em{font-style:normal;font-size:14px;color:var(--muted)}
        .drop .browse{color:var(--accent);font-weight:500}
        input{display:none}
        .status{margin-top:18px;font-size:14px;color:var(--muted);text-align:center;min-height:19px}
        .progress-head{display:flex;justify-content:space-between;align-items:baseline;margin-top:20px}
        .progress-title{font-size:14px;font-weight:600}
        .progress-percent{font-size:13px;font-variant-numeric:tabular-nums;color:var(--muted)}
        .track{height:4px;border-radius:99px;background:var(--track);overflow:hidden;margin-top:10px}
        .fill{height:100%;width:0;border-radius:inherit;background:var(--fill);transition:width .12s linear}
        .progress-detail{display:flex;justify-content:space-between;align-items:baseline;gap:12px;margin-top:9px}
        .progress-file{font-size:13px;color:var(--muted);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
        .progress-count{font-size:13px;color:var(--muted);font-variant-numeric:tabular-nums;flex:none}
        .retry{display:block;margin:18px auto 0;border:0;border-radius:999px;padding:10px 22px;background:var(--fill);color:#fff;font:inherit;font-size:14px;font-weight:600;cursor:pointer;-webkit-tap-highlight-color:transparent}
        .retry:active{opacity:.85}
        .foot{margin-top:22px;font-size:12px;color:var(--muted);line-height:1.45}
        </style>
        </head>
        <body>
        <div class="wrap">
        <main>
        <div class="wordmark">
        <svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M7.5 10V8a4.5 4.5 0 0 1 9 0v2" stroke="var(--accent)" stroke-width="2" stroke-linecap="round"/><rect x="5" y="10" width="14" height="10.5" rx="3.4" fill="var(--accent)"/></svg>
        <span>Vaulthalla</span>
        </div>
        <section class="card">
        <label class="drop" id="drop">
        <svg viewBox="0 0 46 46" fill="none" aria-hidden="true"><path d="M23 7v22m0 0-7.5-7.5M23 29l7.5-7.5" stroke="var(--accent)" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round"/><path d="M9 32v3a5 5 0 0 0 5 5h18a5 5 0 0 0 5-5v-3" stroke="var(--muted)" stroke-width="2.6" stroke-linecap="round"/></svg>
        <strong>Drop files here</strong>
        <em>or <span class="browse">browse</span> — photos and videos</em>
        <input id="files" type="file" accept="image/*,video/*" multiple>
        </label>
        <div class="status" id="queue">Ready for files.</div>
        <div id="progress-card" hidden>
        <div class="progress-head">
        <span class="progress-title" id="progress-title">Uploading…</span>
        <span class="progress-percent" id="progress-percent">0%</span>
        </div>
        <div class="track"><div class="fill" id="progress-fill"></div></div>
        <div class="progress-detail">
        <span class="progress-file" id="progress-file">—</span>
        <span class="progress-count" id="progress-count">0 of 0</span>
        </div>
        </div>
        </section>
        <p class="foot">Files are encrypted on your device before they enter your vault. Nothing is stored on the network.</p>
        </main>
        </div>
        <script>
        const drop=document.getElementById('drop'),input=document.getElementById('files'),queue=document.getElementById('queue'),progressCard=document.getElementById('progress-card'),progressTitle=document.getElementById('progress-title'),progressPercent=document.getElementById('progress-percent'),progressFill=document.getElementById('progress-fill'),progressFile=document.getElementById('progress-file'),progressCount=document.getElementById('progress-count'),endpoint="\(endpoint)";let files=[],current=0,totalBytes=0,sentBytes=0,currentBytes=0,uploading=false,retryButton;
        drop.addEventListener('click',()=>input.click());input.addEventListener('change',()=>add(input.files));['dragenter','dragover'].forEach(e=>drop.addEventListener(e,ev=>{ev.preventDefault();drop.classList.add('over')}));['dragleave','drop'].forEach(e=>drop.addEventListener(e,ev=>{ev.preventDefault();drop.classList.remove('over')}));drop.addEventListener('drop',ev=>add(ev.dataTransfer.files));
        function plural(n){return n===1?'':'s'}function add(list){const accepted=[...list].filter(f=>f.type.startsWith('image/')||f.type.startsWith('video/'));if(!accepted.length){queue.textContent='Choose a photo or video';return}files.push(...accepted);totalBytes+=accepted.reduce((sum,file)=>sum+file.size,0);progressCard.hidden=false;queue.textContent=files.length+' file'+plural(files.length)+' selected';updateProgress();if(!uploading)uploadNext()}function updateProgress(){const total=totalBytes||1,done=Math.min(sentBytes+currentBytes,total),percent=Math.min(100,Math.round(done/total*100));progressPercent.textContent=percent+'%';progressFill.style.width=percent+'%';progressCount.textContent=Math.min(current,files.length)+' of '+files.length}function errorMessage(xhr){try{return JSON.parse(xhr.responseText).error||'Import failed'}catch{return 'Import failed'}}function showRetry(){if(retryButton)return;retryButton=document.createElement('button');retryButton.textContent='Try again';retryButton.type='button';retryButton.className='retry';retryButton.onclick=()=>{retryButton.remove();retryButton=null;uploadNext()};progressCard.appendChild(retryButton)}function clearRetry(){if(retryButton){retryButton.remove();retryButton=null}}function uploadNext(){clearRetry();if(current>=files.length){uploading=false;currentBytes=0;progressTitle.textContent='Import complete';progressFile.textContent=files.length+' file'+plural(files.length)+' imported';queue.textContent='Ready for more files';updateProgress();return}uploading=true;const file=files[current];currentBytes=0;progressTitle.textContent='Uploading';progressFile.textContent=file.name;progressCount.textContent=current+' of '+files.length;const xhr=new XMLHttpRequest();xhr.open('POST',endpoint);xhr.setRequestHeader('X-Filename',encodeURIComponent(file.name));xhr.setRequestHeader('X-Mime-Type',file.type||'application/octet-stream');xhr.upload.onprogress=e=>{if(e.lengthComputable){currentBytes=e.loaded;updateProgress()}};xhr.onload=()=>{if(xhr.status===201||xhr.status===200){sentBytes+=file.size;currentBytes=0;current++;queue.textContent=current+' of '+files.length+' imported';updateProgress();uploadNext()}else{uploading=false;currentBytes=0;progressTitle.textContent='Could not import';progressFile.textContent=errorMessage(xhr);queue.textContent='The upload stopped';showRetry();updateProgress()}};xhr.onerror=()=>{uploading=false;currentBytes=0;progressTitle.textContent='Connection lost';progressFile.textContent='Check the Wi-Fi connection';queue.textContent='The upload stopped';showRetry();updateProgress()};xhr.send(file)}
        </script>
        </body>
        </html>
        """
    }
}

