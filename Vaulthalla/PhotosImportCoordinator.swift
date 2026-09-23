import Foundation
import SwiftUI
import CryptoKit
import Photos
import PhotosUI
import UniformTypeIdentifiers

struct PhotosImportAsset {
    let item: PhotosPickerItem
    let assetIdentifier: String
}

enum PhotosImportError: LocalizedError {
    case missingAssetIdentifier
    case assetNotFound
    case unsupportedResource
    case resourceRequestFailed(Error)

    var errorDescription: String? {
        switch self {
        case .missingAssetIdentifier:
            return "Photos did not provide a local asset identifier."
        case .assetNotFound:
            return "The selected Photos asset is no longer available."
        case .unsupportedResource:
            return "The selected Photos asset has no importable original resource."
        case .resourceRequestFailed(let error):
            return error.localizedDescription
        }
    }
}

struct PhotosImportCoordinator {
    /// Waits for the photo-library authorization decision (system prompt on first use).
    /// Fetching assets by identifier requires the user to have answered the prompt;
    /// racing the prompt makes every fetch fail.
    static func awaitAuthorization() async -> PHAuthorizationStatus {
        await PHPhotoLibrary.requestAuthorization(for: .readWrite)
    }

    /// §6 — small preview pulled straight from the Photos library (image or video
    /// poster frame) at thumbnail size; no full-resolution data is fetched.
    static func thumbnail(for item: PhotosPickerItem) async -> Data? {
        guard let identifier = item.itemIdentifier,
              let asset = PHAsset.fetchAssets(withLocalIdentifiers: [identifier], options: nil).firstObject else {
            return nil
        }
        let options = PHImageRequestOptions()
        options.isNetworkAccessAllowed = true
        options.resizeMode = .fast
        options.deliveryMode = .highQualityFormat
        let manager = PHCachingImageManager()
        var image: UIImage?
        await withCheckedContinuation { continuation in
            manager.requestImage(
                for: asset,
                targetSize: CGSize(width: 1024, height: 1024),
                contentMode: .aspectFill,
                options: options
            ) { result, _ in
                image = result
                continuation.resume()
            }
        }
        return image?.jpegData(compressionQuality: 0.7)
    }

    func importAsset(_ item: PhotosPickerItem, into store: VaultStore, rootKey: SymmetricKey) async throws -> MediaRecord? {
        guard let identifier = item.itemIdentifier else {
            throw PhotosImportError.missingAssetIdentifier
        }

        let result = PHAsset.fetchAssets(withLocalIdentifiers: [identifier], options: nil)
        guard let asset = result.firstObject else {
            throw PhotosImportError.assetNotFound
        }
        return try await importPHAsset(asset, into: store, rootKey: rootKey)
    }

    /// Imports a library asset directly — used by pending-import resume, where
    /// the original PhotosPickerItem no longer exists and only the asset
    /// identifier survived.
    func importPHAsset(_ asset: PHAsset, into store: VaultStore, rootKey: SymmetricKey) async throws -> MediaRecord? {
        let resources = PHAssetResource.assetResources(for: asset)
        let resource: PHAssetResource?
        switch asset.mediaType {
        case .image:
            resource = firstResource(in: resources, preferred: .fullSizePhoto, fallback: .photo)
        case .video:
            resource = firstResource(in: resources, preferred: .fullSizeVideo, fallback: .video)
        default:
            resource = nil
        }
        guard let resource else {
            throw PhotosImportError.unsupportedResource
        }

        let stream = makeStream(for: resource)
        let mimeType = resource.contentType.preferredMIMEType ?? "application/octet-stream"
        return try await store.importStream(
            stream,
            filename: resource.originalFilename,
            mimeType: mimeType,
            rootKey: rootKey
        )
    }

    private func firstResource(
        in resources: [PHAssetResource],
        preferred: PHAssetResourceType,
        fallback: PHAssetResourceType
    ) -> PHAssetResource? {
        if let preferredResource = resources.first(where: { $0.type == preferred }) {
            return preferredResource
        }
        return resources.first(where: { $0.type == fallback })
    }

    private func makeStream(for resource: PHAssetResource) -> AsyncThrowingStream<Data, Error> {
        AsyncThrowingStream { continuation in
            let manager = PHAssetResourceManager.default()
            let options = PHAssetResourceRequestOptions()
            options.isNetworkAccessAllowed = true

            let requestID = manager.requestData(
                for: resource,
                options: options,
                dataReceivedHandler: { data in
                    continuation.yield(data)
                },
                completionHandler: { error in
                    if let error {
                        continuation.finish(throwing: PhotosImportError.resourceRequestFailed(error))
                    } else {
                        continuation.finish()
                    }
                }
            )

            continuation.onTermination = { @Sendable _ in
                if requestID != PHInvalidAssetResourceDataRequestID {
                    manager.cancelDataRequest(requestID)
                }
            }
        }
    }
}
