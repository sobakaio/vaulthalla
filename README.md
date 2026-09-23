<p align="center">
  <img src="Vaulthalla/Assets.xcassets/VaultMark.imageset/VaultMark.png" width="160" alt="Vaulthalla vault mark">
</p>

<h1 align="center">Vaulthalla</h1>

<p align="center">
  <strong>A privacy-first, offline photo and video vault for iPhone.</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/platform-iOS%2026%2B-000000?style=flat-square&logo=apple&logoColor=white" alt="iOS 26+">
  <img src="https://img.shields.io/badge/Swift-SwiftUI-F05138?style=flat-square&logo=swift&logoColor=white" alt="Swift and SwiftUI">
  <img src="https://img.shields.io/badge/crypto-AES--GCM-5B21B6?style=flat-square&logo=letsencrypt&logoColor=white" alt="AES-GCM encryption">
  <img src="https://img.shields.io/badge/cloud-none-1F2937?style=flat-square&logo=icloud&logoColor=white" alt="No cloud">
</p>

<p align="center">
  An encrypted, device-bound vault—not a cloud service. No account, cloud sync, analytics, telemetry, or remote access is required for the normal vault experience.
</p>

---

## What it does

Vaulthalla imports photos and videos into an encrypted on-device library. Once unlocked, it provides separate Images and Videos libraries, automatic filename-based grouping, full-screen viewing, playback, slideshow controls, media information, multi-selection, and permanent deletion.

The vault is deliberately **one-way**: it does not offer export, sharing, Save to Photos, Save to Files, or drag-out access to vault media.

### Import media your way

Vaulthalla supports four user-controlled import paths:

- **Photos** — select images and videos from the iPhone photo library.
- **Files** — import media selected with the system Files picker.
- **USB / Finder File Sharing** — transfer media over a cable to Vaulthalla’s File Sharing inbox, then explicitly import the waiting files from inside the app.
- **Local Web Import** — start a temporary local web server, then upload from a browser on another device connected to the same LAN.

An optional **Delete originals after successful import** choice is available for imports. An original is considered for deletion only after its encrypted vault copy has committed successfully.

Imports stream data rather than loading a large video all at once. Original media bytes are retained unchanged, and SHA-256 duplicate detection avoids storing the same source twice—even when it has a different name. The app reports imported, duplicate, failed, and retained-source results after an import.

### Browse and view privately

- Image and video libraries are separate.
- Compatible filenames are automatically organized into deterministic groups; unmatched files remain available in **Ungrouped**.
- Group and item grids use encrypted thumbnails.
- Image viewing supports fit/fill, pinch zoom, pan, and double-tap zoom.
- Video playback supports native controls, autoplay and looping preferences, and fit/fill modes.
- Slideshows and video playlists stay within the open group.
- An item’s original filename, size, type, and import date are available only in its unlocked info view.
- Multi-select items or whole groups for immediate, confirmed deletion. There is no Trash or undo.

## Security by design

Vaulthalla is built around the principle that the vault should be useless without both the user’s password and the original device.

| Security property | How Vaulthalla applies it |
| --- | --- |
| **Offline by default** | No account, cloud sync, telemetry, analytics, or remote vault access. |
| **Two-part unlock** | The vault needs the master password and a device-only Keychain secret. |
| **Authenticated encryption** | AES-GCM protects encrypted media, metadata, thumbnails, and structural integrity. |
| **Independent media keys** | Every imported item has its own random 256-bit key. |
| **Minimal lock-screen leakage** | Vault contents, counts, storage, groups, and activity stay hidden until unlock. |
| **One-way vault** | No export, sharing, Save to Photos, or Save to Files from the vault. |
| **Fail closed** | Verification reports corrupted data; it does not silently repair or delete it. |

### Device-bound encryption

- A random 256-bit Vault Root Key encrypts the vault.
- The root key is wrapped with a key derived from the master password **and** a random device secret.
- The device secret lives in the iOS Keychain with `ThisDeviceOnly` protection and does not synchronize through iCloud Keychain.
- Copying the vault container to another device is not enough to unlock it, even with the password.

### Password protection

- Master passwords support Unicode and must be 8–128 characters long.
- Password keys use PBKDF2-HMAC-SHA256 with a random salt.
- The work factor is calibrated when the vault is created to make password derivation deliberately expensive on that device.
- The password is not used to encrypt every media file directly.

### Encrypted media storage

- Each imported item receives its own random 256-bit media key.
- Media is encrypted in 1 MiB chunks using AES-GCM authenticated encryption.
- Chunk keys are derived with HKDF and are domain-separated by item, chunk number, and vault format.
- Encrypted metadata holds item details, keys, hashes, and thumbnails. Exact item sizes remain inside encrypted metadata.
- Fixed-size padded chunks reduce leakage of an individual item’s exact size.
- Integrity authentication detects modified or corrupted encrypted content.

### Access and screen protection

- Before unlock, the app shows a neutral lock screen—not thumbnails, media counts, storage use, groups, or recent activity.
- Password unlock is always available. Optional PIN and Face ID convenience unlock can be enabled on the device.
- Failed unlocks are rate-limited with increasing delays.
- An optional auto-destroy policy can destroy vault keys and remove the vault after a configured number of failed password attempts.
- The app locks when it leaves the foreground. Screenshot and screen-recording protection can cover the interface and lock the vault when capture is detected.
- An opaque privacy cover protects the App Switcher preview.
- Security Activity is encrypted and available only after the vault is unlocked.

## Local Web Import

Web Import is a convenience transfer feature, not remote access or synchronization.

When an unlocked user explicitly starts it, Vaulthalla runs a temporary local web server and shows a private-network URL. Open that URL in a browser on **another device connected to the same LAN** to upload media directly into the vault. Its design is intentionally narrow:

- It accepts browser uploads only; it cannot list, browse, search, download, or otherwise expose vault content.
- Every session has a fresh cryptographically random token.
- Only the import page and authenticated upload route are accepted.
- Uploads stream directly into encrypted storage rather than being staged as plaintext files.
- The listener stops when the user stops it, the vault locks, the app backgrounds, or the session expires.

## Vault maintenance

While the vault is unlocked, Vaulthalla can:

- **Verify Vault** — authenticate encrypted chunks, validate the encrypted index, recompute item hashes, and report corruption without silently repairing or deleting data.
- **Compact Vault** — reclaim physical space from reusable encrypted chunks after deletions, without creating plaintext vault media on disk.
- Show encrypted-storage statistics, integrity state, and the last successful verification time.

Long imports and maintenance tasks are transactional and can use best-effort continued processing where iOS permits. Sensitive UI still locks when the app backgrounds.

## Privacy boundaries

Vaulthalla has no password recovery, recovery phrase, reset path, or cloud recovery. Losing the master password, the device-binding secret, the app container, or the device can make the vault permanently inaccessible.

Vault data, encrypted audit data, and app-managed import staging are excluded from device backups. Keychain material is device-only and does not migrate to another device.

Deleting an item destroys its active key and removes it from the vault state. As with all flash storage, Vaulthalla does not claim guaranteed physical overwrite of every historical byte.

The USB/Finder inbox is an intentional plaintext staging area until the user imports or removes its files. Photos and Files imports may ask Apple’s system pickers to retrieve media the user explicitly selects, including from iCloud-backed libraries or drives. Those system-managed transfers are separate from Vaulthalla’s normal local-only vault behavior.

## Built with Apple frameworks

Vaulthalla is a native SwiftUI iOS app. It uses Apple frameworks including CryptoKit, Security/Keychain, LocalAuthentication, CommonCrypto, Photos/PhotosUI, AVFoundation, Network, and UniformTypeIdentifiers. It has no third-party SDK dependencies.

## Requirements

- Xcode with the iOS 26 SDK
- iPhone running iOS 26 or later

Open `Vaulthalla.xcodeproj` in Xcode, choose an iPhone destination, and run the **Vaulthalla** scheme.
