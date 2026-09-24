import Foundation
import AVFoundation
import CryptoKit
import ImageIO
import Observation

/// A one-shot box that lets a synchronous thread wait for an async result.
/// The wait only ever parks this delegate-queue thread for the duration of one
/// bounded chunk read; the response is delivered by the producing Task.
private final class ResultBox: @unchecked Sendable {
    private let lock = NSLock()
    private let semaphore = DispatchSemaphore(value: 0)
    private var value: (data: Data?, error: Error?)?
    private var done = false

    func finish(_ value: (data: Data?, error: Error?)) {
        lock.lock()
        if !done {
            self.value = value
            done = true
        }
        lock.unlock()
        semaphore.signal()
    }

    func wait() -> (data: Data?, error: Error?) {
        semaphore.wait()
        lock.lock()
        defer { lock.unlock() }
        return value ?? (data: nil, error: NSError(domain: "VaultVideoAssetProvider", code: -2))
    }
}

/// Serves a decrypted vault video to AVFoundation strictly in memory.
///
/// AVFoundation fetches bounded byte ranges through this resource-loader
/// delegate; each range is decrypted on demand from the block store.
/// Plaintext bytes never reach disk and the full movie is never materialized.
final class VaultVideoAssetProvider: NSObject, AVAssetResourceLoaderDelegate, @unchecked Sendable {
    private let readRange: @Sendable (Int64, Int64) async throws -> Data
    private let mimeType: String
    private let byteCount: Int64
    private let assetIdentifier = UUID().uuidString
    private let delegateQueue = DispatchQueue(label: "Vaulthalla.video-asset-provider", target: nil)
    private let pendingRequests: NSLock = NSLock()
    private var activeRequests: [AVAssetResourceLoadingRequest] = []

    /// - Parameter readRange: returns the decoded bytes for `offset..<offset+length`;
    ///   ranges past the end are clamped to the record's real length.
    init(mimeType: String, byteCount: Int64, readRange: @escaping @Sendable (Int64, Int64) async throws -> Data) {
        self.readRange = readRange
        self.mimeType = mimeType
        self.byteCount = byteCount
    }

    /// Declares the QuickTime-family content type that matches the record's
    /// MIME type, so the demuxer selects the right container parser.
    private static func contentType(for mimeType: String) -> String {
        switch mimeType {
        case "video/quicktime":
            return "com.apple.quicktime"
        case "video/x-m4v":
            return "com.apple.m4v"
        default:
            return "com.apple.mpeg-4"
        }
    }

    deinit {
        pendingRequests.lock()
        activeRequests.removeAll()
        pendingRequests.unlock()
    }

    /// Builds an AVAsset whose data is streamed through this provider. The asset
    /// keeps the provider alive for the duration of its loading callbacks.
    func makeAsset() async throws -> AVAsset {
        // The URL path carries a real file extension: without one,
        // AVFoundation cannot decide the container format from the probe
        // data alone and rejects the asset ("media format is not supported").
        let url = URL(string: "vaultmedia://vaulthalla/vault-\(assetIdentifier).\(Self.fileExtension(for: mimeType))")!
        let asset = AVURLAsset(url: url)
        // The loader keeps the delegate weakly, so callers must retain this
        // provider (or the asset) for as long as the asset may issue reads.
        asset.resourceLoader.setDelegate(self, queue: delegateQueue)
        try await asset.load(.isPlayable)
        return asset
    }

    private static func fileExtension(for mimeType: String) -> String {
        switch mimeType {
        case "video/quicktime":
            return "mov"
        case "video/x-m4v":
            return "m4v"
        default:
            return "mp4"
        }
    }

    func resourceLoader(_ resourceLoader: AVAssetResourceLoader,
                        shouldWaitForLoadingOfRequestedResource loadingRequest: AVAssetResourceLoadingRequest) -> Bool {
        guard let requestURL = loadingRequest.request.url,
              let components = URLComponents(url: requestURL, resolvingAgainstBaseURL: false) else {
            return false
        }
        // The asset identifier is the URL's last path component minus its
        // extension, e.g. vaultmedia://vaulthalla/vault-<UUID>.mp4
        let name = (components.path as NSString).lastPathComponent
        let identifier = (name as NSString).deletingPathExtension
        guard identifier == "vault-\(assetIdentifier)",
              !loadingRequest.isCancelled else {
            return false
        }
        // The loader holds the delegate weakly and the request transiently;
        // keep a strong reference for the duration of the async read.
        pendingRequests.lock()
        activeRequests.append(loadingRequest)
        pendingRequests.unlock()
        serve(loadingRequest)
        return true
    }

    func resourceLoader(_ resourceLoader: AVAssetResourceLoader,
                        didCancel loadingRequest: AVAssetResourceLoadingRequest) {
        release(loadingRequest)
        loadingRequest.finishLoading()
    }

    private func release(_ loadingRequest: AVAssetResourceLoadingRequest) {
        pendingRequests.lock()
        activeRequests.removeAll { $0 === loadingRequest }
        pendingRequests.unlock()
    }

    private func serve(_ loadingRequest: AVAssetResourceLoadingRequest) {
        guard !loadingRequest.isCancelled else {
            release(loadingRequest)
            loadingRequest.finishLoading()
            return
        }
        if let infoRequest = loadingRequest.contentInformationRequest {
            infoRequest.contentType = Self.contentType(for: mimeType)
            infoRequest.contentLength = byteCount
            infoRequest.isByteRangeAccessSupported = true
            infoRequest.isEntireLengthAvailableOnDemand = true
        }
        guard let dataRequest = loadingRequest.dataRequest else {
            release(loadingRequest)
            loadingRequest.finishLoading()
            return
        }
        let offset = dataRequest.requestedOffset
        // Clamp: the demuxer may probe just past EOF, and an "all data to end"
        // request reports requestedLength as NSIntegerMax.
        let length = Swift.max(0, Swift.min(Int64(dataRequest.requestedLength), byteCount - offset))
        // Serve synchronously on this serial delegate queue: the loader
        // spins its own run loop until finishLoading, so the response must not
        // depend on any other actor or thread being scheduled. The read path
        // (block-store actors) never touches this queue, so parking it here
        // cannot deadlock.
        let box = ResultBox()
        Task {
            do {
                let data = try await self.readRange(offset, length)
                box.finish((data: data, error: nil))
            } catch {
                box.finish((data: nil, error: error))
            }
        }
        let result = box.wait()
        if let data = result.data {
            dataRequest.respond(with: data)
            loadingRequest.finishLoading()
        } else {
            let error = result.error ?? NSError(domain: "VaultVideoAssetProvider", code: -1)
            loadingRequest.finishLoading(with: error)
        }
        release(loadingRequest)
    }
}

@Observable
@MainActor
final class VaultVideoPlayerModel {
    static let tempFilePrefix = "vaultplay-"

    private(set) var player: AVPlayer?
    @ObservationIgnored private var endObserver: NSObjectProtocol?
    /// Keeps the in-memory resource loader alive while the asset may still
    /// issue range reads.
    @ObservationIgnored private var provider: VaultVideoAssetProvider?
    @ObservationIgnored var onFinished: (() -> Void)?

    /// Streams the video through an in-memory resource loader and plays it.
    /// Decrypted bytes exist only in memory; nothing is written to disk.
    func prepare(record: MediaRecord, rootKey: SymmetricKey, loops: Bool = false) async {
        stop()
        do {
            let provider = Self.makeProvider(for: record, rootKey: rootKey)
            let asset = try await provider.makeAsset()
            guard !Task.isCancelled else {
                return
            }
            setUpPlayer(asset: asset, loops: loops, provider: provider)
        } catch {
            return
        }
    }

    /// Builds a resource loader that serves bounded byte ranges of the record
    /// through the authenticated block-store API.
    static func makeProvider(for record: MediaRecord, rootKey: SymmetricKey) -> VaultVideoAssetProvider {
        VaultVideoAssetProvider(
            mimeType: record.mimeType,
            byteCount: record.byteCount
        ) { offset, length in
            try await VaultStore.shared.readMedia(
                record,
                range: offset..<(offset + length),
                using: rootKey
            )
        }
    }

    func setUpPlayer(asset: AVAsset, loops: Bool, provider: VaultVideoAssetProvider? = nil) {
        stop()
        self.provider = provider
        let item = AVPlayerItem(asset: asset)
        endObserver = NotificationCenter.default.addObserver(
            forName: .AVPlayerItemDidPlayToEndTime,
            object: item,
            queue: .main
        ) { [weak self] _ in
            guard let self else { return }
            if loops {
                Task { @MainActor in
                    await self.player?.seek(to: .zero)
                    self.player?.play()
                }
            } else {
                self.onFinished?()
            }
        }
        player = AVPlayer(playerItem: item)
        // The source is a complete local file, not a network stream.
        player?.automaticallyWaitsToMinimizeStalling = false
    }

    func stop() {
        player?.pause()
        if let endObserver {
            NotificationCenter.default.removeObserver(endObserver)
        }
        endObserver = nil
        player = nil
        provider = nil
    }

    func play() {
        player?.play()
    }

    func pause() {
        player?.pause()
    }

    /// Removes playback temp files orphaned by an older app version (which
    /// decrypted to disk) or a previous launch that ended abruptly.
    nonisolated static func sweepStaleTempFiles() {
        let fm = FileManager.default
        let urls = (try? fm.contentsOfDirectory(
            at: fm.temporaryDirectory,
            includingPropertiesForKeys: nil
        )) ?? []
        for url in urls where url.lastPathComponent.hasPrefix(tempFilePrefix) {
            try? fm.removeItem(at: url)
        }
    }
}

/// §6 — builds small JPEG previews. Works on files and in-memory bytes; never writes
/// plaintext to disk.
enum ThumbnailGenerator {
    static let tempFilePrefix = "vaultthumb-"

    /// 1024 px keeps 3× Retina tiles (≈440 px wide) sharp; 640 px read
    /// as visibly soft on Pro Max screens.
    static let maxPixelSize: CGFloat = 1024
    static let jpegQuality: CGFloat = 0.7

    static func fromURL(_ url: URL, isVideo: Bool) async -> Data? {
        if isVideo {
            guard let cg = await firstVideoFrame(from: url) else { return nil }
            return jpegData(from: cg)
        }
        guard let source = CGImageSourceCreateWithURL(url as CFURL, [kCGImageSourceShouldCache: false] as CFDictionary) else { return nil }
        guard let cg = thumbnailCGImage(from: source) else { return nil }
        return jpegData(from: cg)
    }

    static func fromImageData(_ data: Data) -> Data? {
        guard let source = CGImageSourceCreateWithData(data as CFData, [kCGImageSourceShouldCache: false] as CFDictionary) else { return nil }
        guard let cg = thumbnailCGImage(from: source) else { return nil }
        return jpegData(from: cg)
    }

    /// Poster for a vault video served in memory. The provider is kept alive
    /// for the whole frame fetch; decrypted bytes never reach disk.
    static func fromVideoAsset(provider: VaultVideoAssetProvider, record: MediaRecord,
                               rootKey: SymmetricKey) async -> Data? {
        guard let asset = try? await provider.makeAsset() else { return nil }
        guard let cg = await firstVideoFrame(from: asset) else { return nil }
        return jpegData(from: cg)
    }

    /// Removes poster-generation files left behind if the app was terminated
    /// before its normal `defer` cleanup ran.
    nonisolated static func sweepStaleTempFiles() {
        let fm = FileManager.default
        let urls = (try? fm.contentsOfDirectory(at: fm.temporaryDirectory, includingPropertiesForKeys: nil)) ?? []
        for url in urls where url.lastPathComponent.hasPrefix(tempFilePrefix) {
            try? fm.removeItem(at: url)
        }
    }

    private static func thumbnailCGImage(from source: CGImageSource) -> CGImage? {
        let options: [CFString: Any] = [
            kCGImageSourceCreateThumbnailFromImageAlways: true,
            kCGImageSourceCreateThumbnailWithTransform: true,
            kCGImageSourceShouldCacheImmediately: true,
            kCGImageSourceThumbnailMaxPixelSize: maxPixelSize
        ]
        return CGImageSourceCreateThumbnailAtIndex(source, 0, options as CFDictionary)
    }

    private static func firstVideoFrame(from url: URL) async -> CGImage? {
        await firstVideoFrame(from: AVAsset(url: url))
    }

    private static func firstVideoFrame(from asset: AVAsset) async -> CGImage? {
        let generator = AVAssetImageGenerator(asset: asset)
        generator.appliesPreferredTrackTransform = true
        generator.maximumSize = CGSize(width: maxPixelSize, height: maxPixelSize)
        let target = CMTime(seconds: 0.1, preferredTimescale: 600)
        if let frame = try? await generator.image(at: target) {
            return frame.image
        }
        if let frame = try? await generator.image(at: .zero) {
            return frame.image
        }
        return nil
    }

    private static func jpegData(from cg: CGImage) -> Data? {
        let data = NSMutableData()
        guard let destination = CGImageDestinationCreateWithData(data, "public.jpeg" as CFString, 1, nil) else { return nil }
        CGImageDestinationAddImage(destination, cg, [kCGImageDestinationLossyCompressionQuality: jpegQuality] as CFDictionary)
        guard CGImageDestinationFinalize(destination) else { return nil }
        return data as Data
    }
}
