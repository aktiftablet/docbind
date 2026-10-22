import Foundation
import UIKit
import Security
import React

/// RSA keys live in Keychain, not Secure Enclave. Screen capture detection cannot prevent screenshots.
@objc(DocBindScreenGuard)
class DocBindModule: RCTEventEmitter {
    private var captureObserver: NSObjectProtocol?
    override static func requiresMainQueueSetup() -> Bool { true }
    override func constantsToExport() -> [AnyHashable: Any]! { ["keyAlgorithm": "RSA-OAEP-256"] }
    override func supportedEvents() -> [String]! { ["DocBindCaptureChanged"] }
    override func startObserving() {
        captureObserver = NotificationCenter.default.addObserver(
            forName: UIScreen.capturedDidChangeNotification, object: nil, queue: .main
        ) { [weak self] _ in self?.sendEvent(withName: "DocBindCaptureChanged", body: UIScreen.main.isCaptured) }
    }
    override func stopObserving() {
        if let observer = captureObserver { NotificationCenter.default.removeObserver(observer) }
        captureObserver = nil
    }
    deinit { if let observer = captureObserver { NotificationCenter.default.removeObserver(observer) } }

    @objc(isScreenCaptured:rejecter:)
    func isScreenCaptured(_ resolve: @escaping RCTPromiseResolveBlock, rejecter reject: RCTPromiseRejectBlock) {
        DispatchQueue.main.async { resolve(UIScreen.main.isCaptured) }
    }
    private func query(_ alias: String) -> [String: Any] {
        [kSecClass as String: kSecClassKey,
         kSecAttrApplicationTag as String: Data(alias.utf8),
         kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
         kSecAttrKeyClass as String: kSecAttrKeyClassPrivate]
    }
    private func privateKey(_ alias: String) throws -> SecKey {
        var q = query(alias); q[kSecReturnRef as String] = true
        var result: CFTypeRef?
        let status = SecItemCopyMatching(q as CFDictionary, &result)
        guard status == errSecSuccess, let value = result else { throw NSError(domain: NSOSStatusErrorDomain, code: Int(status)) }
        return value as! SecKey
    }
    @objc(hasKeyPair:resolver:rejecter:)
    func hasKeyPair(_ alias: String, resolver resolve: RCTPromiseResolveBlock, rejecter reject: RCTPromiseRejectBlock) {
        var q = query(alias); q[kSecReturnRef as String] = true
        var result: CFTypeRef?
        let status = SecItemCopyMatching(q as CFDictionary, &result)
        if status == errSecSuccess { resolve(true) }
        else if status == errSecItemNotFound { resolve(false) }
        else { reject("KEYSTORE_ERROR", "Keychain unavailable", NSError(domain: NSOSStatusErrorDomain, code: Int(status))) }
    }
    private func der(_ tag: UInt8, _ data: Data) -> Data {
        var length = data.count
        var lengthBytes = [UInt8]()
        if length < 128 { lengthBytes = [UInt8(length)] }
        else {
            while length > 0 { lengthBytes.insert(UInt8(length & 255), at: 0); length >>= 8 }
            lengthBytes.insert(0x80 | UInt8(lengthBytes.count), at: 0)
        }
        return Data([tag] + lengthBytes) + data
    }
    private func publicPem(_ key: SecKey) throws -> String {
        var error: Unmanaged<CFError>?
        guard let pub = SecKeyCopyPublicKey(key), let pkcs1 = SecKeyCopyExternalRepresentation(pub, &error) as Data? else {
            if let failure = error?.takeRetainedValue() { throw failure }
            throw NSError(domain: "DocBind", code: 1)
        }
        let rsaAlgorithm = Data([0x30,0x0d,0x06,0x09,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,0x01,0x05,0x00])
        let spki = der(0x30, rsaAlgorithm + der(0x03, Data([0]) + pkcs1))
        let body = spki.base64EncodedString(options: [.lineLength64Characters, .endLineWithLineFeed])
        return "-----BEGIN PUBLIC KEY-----\n\(body)\n-----END PUBLIC KEY-----"
    }
    @objc(generateRsaKeyPair:resolver:rejecter:)
    func generateRsaKeyPair(_ alias: String, resolver resolve: RCTPromiseResolveBlock, rejecter reject: RCTPromiseRejectBlock) {
        // Never overwrite an existing private key.
        var lookup = query(alias); lookup[kSecReturnRef as String] = true
        var existing: CFTypeRef?
        let status = SecItemCopyMatching(lookup as CFDictionary, &existing)
        if status == errSecSuccess, let existingKey = existing {
            do { resolve(try publicPem(existingKey as! SecKey)) } catch { reject("KEYSTORE_ERROR", error.localizedDescription, error) }
            return
        }
        guard status == errSecItemNotFound else {
            reject("KEYSTORE_ERROR", "Keychain unavailable", NSError(domain: NSOSStatusErrorDomain, code: Int(status))); return
        }
        var error: Unmanaged<CFError>?
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits as String: 2048,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: Data(alias.utf8),
                kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
            ]
        ]
        guard let key = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            reject("KEYGEN_ERROR", "RSA key generation failed", error?.takeRetainedValue()); return
        }
        do { resolve(try publicPem(key)) } catch { reject("KEYSTORE_ERROR", error.localizedDescription, error) }
    }
    @objc(getPublicKeyPem:resolver:rejecter:)
    func getPublicKeyPem(_ alias: String, resolver resolve: RCTPromiseResolveBlock, rejecter reject: RCTPromiseRejectBlock) {
        do { resolve(try publicPem(privateKey(alias))) } catch { reject("KEYSTORE_ERROR", error.localizedDescription, error) }
    }
    @objc(rsaOaepDecrypt:encryptedDekBase64:resolver:rejecter:)
    func rsaOaepDecrypt(_ alias: String, encryptedDekBase64: String, resolver resolve: RCTPromiseResolveBlock, rejecter reject: RCTPromiseRejectBlock) {
        do {
            let key = try privateKey(alias)
            guard let ciphertext = Data(base64Encoded: encryptedDekBase64) else { throw NSError(domain: "DocBind", code: 2) }
            var error: Unmanaged<CFError>?
            guard var plaintext = SecKeyCreateDecryptedData(key, .rsaEncryptionOAEPSHA256, ciphertext as CFData, &error) as Data? else {
                reject("DECRYPT_ERROR", "RSA decryption failed", error?.takeRetainedValue()); return
            }
            resolve(plaintext.base64EncodedString())
            plaintext.resetBytes(in: 0..<plaintext.count)
        } catch { reject("KEYSTORE_ERROR", error.localizedDescription, error) }
    }
}
