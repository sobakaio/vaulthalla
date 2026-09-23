import Foundation

struct ParsedFilename: Equatable {
    let run: String
    let mode: String
    let groupIndex: Int
    let tier: String
    let shotNumber: Int
    let filename: String
}

struct MediaGroup: Identifiable, Equatable {
    let id: String
    let displayName: String
    let items: [MediaRecord]
    let isUngrouped: Bool
}

enum GroupingEngine {
    private static let pattern = #"^(\d{8}_\d{6}_\d{6})_(photoshoot|random)_(\d+)_(production|preview)_shot_(\d+)_"#

    static func parse(_ filename: String) -> ParsedFilename? {
        guard let regex = try? NSRegularExpression(pattern: pattern),
              let match = regex.firstMatch(in: filename, range: NSRange(filename.startIndex..., in: filename)),
              match.numberOfRanges == 6 else { return nil }
        func value(_ index: Int) -> String {
            String(filename[Range(match.range(at: index), in: filename)!])
        }
        return ParsedFilename(run: value(1), mode: value(2), groupIndex: Int(value(3)) ?? 0, tier: value(4), shotNumber: Int(value(5)) ?? 0, filename: filename)
    }

    static func groups(from records: [MediaRecord], mediaPrefix: String) -> [MediaGroup] {
        let records = records.filter { $0.mimeType.hasPrefix(mediaPrefix) }
        let sorted = records.sorted { $0.filename.localizedStandardCompare($1.filename) == .orderedAscending }
        var matched: [String: [MediaRecord]] = [:]
        var firstPosition: [String: Int] = [:]
        var ungrouped: [MediaRecord] = []
        for (position, record) in sorted.enumerated() {
            guard let parsed = parse(record.filename) else { ungrouped.append(record); continue }
            let key = "\(parsed.run):\(parsed.mode):\(parsed.groupIndex):\(parsed.tier)"
            matched[key, default: []].append(record)
            firstPosition[key] = min(firstPosition[key] ?? position, position)
        }
        let orderedKeys = matched.keys.sorted { (firstPosition[$0] ?? .max) < (firstPosition[$1] ?? .max) }
        var result = orderedKeys.enumerated().map { offset, key in
            let items = matched[key, default: []].sorted {
                let a = parse($0.filename)!
                let b = parse($1.filename)!
                return a.shotNumber == b.shotNumber ? $0.filename < $1.filename : a.shotNumber < b.shotNumber
            }
            return MediaGroup(id: key, displayName: mediaPrefix == "image/" ? "Album \(offset + 1)" : "Videos \(offset + 1)", items: items, isUngrouped: false)
        }
        if !ungrouped.isEmpty {
            result.append(MediaGroup(id: "ungrouped-\(mediaPrefix)", displayName: "Ungrouped", items: ungrouped.sorted { $0.filename < $1.filename }, isUngrouped: true))
        }
        return result
    }
}
