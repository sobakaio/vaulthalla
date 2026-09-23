import Testing
import Foundation
@testable import Vaulthalla

struct GroupingTests {
    @Test func normalizesZeroPaddedGroupIndex() {
        let first = GroupingEngine.parse("20260916_152657_755005_random_001_production_shot_137_a.jpg")
        let second = GroupingEngine.parse("20260916_152657_755005_random_1_production_shot_2_b.jpg")
        #expect(first?.groupIndex == 1)
        #expect(second?.groupIndex == 1)
    }

    @Test func numericShotOrdering() {
        let names = [
            "20260916_152657_755005_random_001_production_shot_10_b.jpg",
            "20260916_152657_755005_random_001_production_shot_2_a.jpg"
        ]
        let records = names.enumerated().map { pair in
            let index = pair.offset
            return MediaRecord(id: UUID(), filename: pair.element, byteCount: 1, mimeType: "image/jpeg", importedAt: Date(), sha256: Data([UInt8(index)]), mediaKey: Data(repeating: 1, count: 32), chunks: [ChunkAddress(segment: 0, slot: index)], encryptedThumbnail: nil)
        }
        #expect(GroupingEngine.groups(from: records, mediaPrefix: "image/").first?.items.first?.filename == names[1])
    }

    private func makeRecords(_ files: [(String, String)]) -> [MediaRecord] {
        files.map { name, mime in
            MediaRecord(
                id: UUID(),
                filename: name,
                byteCount: 1,
                mimeType: mime,
                importedAt: Date(),
                sha256: Data(repeating: UInt8(name.count % 251), count: 32),
                mediaKey: Data(repeating: 2, count: 32),
                chunks: [ChunkAddress(segment: 0, slot: 0)],
                encryptedThumbnail: nil
            )
        }
    }

    @Test func groupOrderingFollowsFirstItemPosition() {
        // Group B's first item sorts before group A's first item, so B is "Album 1".
        let records = makeRecords([
            ("20260916_152657_755005_random_001_production_shot_9_a.jpg", "image/jpeg"),
            ("20260916_152657_755004_random_002_production_shot_5_a.jpg", "image/jpeg"),
            ("20260916_152657_755004_random_002_production_shot_1_a.jpg", "image/jpeg")
        ])
        let groups = GroupingEngine.groups(from: records, mediaPrefix: "image/")
        #expect(groups.count == 2)
        #expect(groups[0].displayName == "Album 1")
        #expect(groups[0].items.count == 2)
        #expect(groups[1].displayName == "Album 2")
        #expect(groups[1].items.first?.filename.hasSuffix("_001_production_shot_9_a.jpg") == true)
    }

    @Test func filenameTieBreakerWithinGroup() {
        // Same shot number in two files: deterministic filename-ascending order.
        let records = makeRecords([
            ("20260916_152657_755005_random_001_production_shot_7_zeta.jpg", "image/jpeg"),
            ("20260916_152657_755005_random_001_production_shot_7_alpha.jpg", "image/jpeg")
        ])
        let group = GroupingEngine.groups(from: records, mediaPrefix: "image/").first!
        #expect(group.items.map(\.filename).first?.hasSuffix("_alpha.jpg") == true)
        #expect(group.items.map(\.filename).last?.hasSuffix("_zeta.jpg") == true)
    }

    @Test func ungroupedAlwaysLast() {
        let records = makeRecords([
            ("20260916_152657_755005_random_001_production_shot_1_a.jpg", "image/jpeg"),
            ("plain_photo.jpg", "image/jpeg"),
            ("20260916_152657_755005_random_002_production_shot_1_a.jpg", "image/jpeg")
        ])
        let groups = GroupingEngine.groups(from: records, mediaPrefix: "image/")
        #expect(groups.count == 3)
        #expect(groups.last?.isUngrouped == true)
        #expect(groups.last?.displayName == "Ungrouped")
        #expect(groups.last?.items.map(\.filename) == ["plain_photo.jpg"])
    }

    @Test func imagesAndVideosGroupedIndependently() {
        // Same parsed group key across types must produce separate Albums and Videos.
        let base = "20260916_152657_755005_random_001_production_shot_1_a"
        let records = makeRecords([
            (base + "_image.jpg", "image/jpeg"),
            (base + "_video.mp4", "video/mp4")
        ])
        let images = GroupingEngine.groups(from: records, mediaPrefix: "image/")
        let videos = GroupingEngine.groups(from: records, mediaPrefix: "video/")
        #expect(images.count == 1)
        #expect(images[0].displayName == "Album 1")
        #expect(videos.count == 1)
        #expect(videos[0].displayName == "Videos 1")
        #expect(images[0].items.count == 1)
        #expect(videos[0].items.count == 1)
    }
}
