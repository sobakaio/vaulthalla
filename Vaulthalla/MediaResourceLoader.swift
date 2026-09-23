import Foundation
import AVFoundation
import CryptoKit
import ImageIO
import Observation

@Observable
@MainActor
final class VaultVideoPlayerModel {
    static let tempFilePrefix = "vaultplay-"

    private(set) var player: AVPlayer?
    @ObservationIgnored private var endObserver: NSObjectProtocol?
    @ObservationIgnored private var tempFileURL: URL?
    @ObservationIgnored var onFinished: (() -> Void)?

    /// Decrypts the video into a short-lived, fully-protected temporary file and
    /// plays it from there. The file is NSFileProtectionComplete and is deleted
    /// as soon as playback stops. Vault storage itself never contains plaintext.
    func prepare(record: MediaRecord, rootKey: SymmetricKey, loops: Bool = false) async {
        stop()
        do {
            let fileURL = try await VaultStore.shared.writeMediaToProtectedTemporaryFile(
                record,
                using: rootKey,
                prefix: Self.tempFilePrefix
            )
            guard !Task.isCancelled else {
                try? FileManager.default.removeItem(at: fileURL)
                return
            }
            prepareProtectedFile(at: fileURL, loops: loops)
        } catch {
            return
        }
    }

    /// Takes ownership of a fully authenticated, protected file. The caller
    /// must delete the file if it cancels before handing it to this model.
    func prepareProtectedFile(at fileURL: URL, loops: Bool) {
        stop()
        tempFileURL = fileURL
        let asset = AVURLAsset(url: fileURL)
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
        deleteTempFile()
    }

    func play() {
        player?.play()
    }

    func pause() {
        player?.pause()
    }

    private func deleteTempFile() {
        guard let url = tempFileURL else { return }
        tempFileURL = nil
        try? FileManager.default.removeItem(at: url)
    }

    /// Removes playback temp files orphaned by a previous launch that ended
    /// abruptly (e.g. the app was terminated mid-playback).
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
        let asset = AVAsset(url: url)
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
