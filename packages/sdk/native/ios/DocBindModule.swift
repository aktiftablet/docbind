import Foundation
import UIKit
import Security

/**
 * React Native iOS Native Module for DocBind:
 * 1. Observes UIScreen.capturedDidChangeNotification to blur/hide the secure document viewer
 *    whenever screen recording or AirPlay mirroring is active.
 * 2. Stores non-extractable RSA-OAEP 2048 private keys in the iOS Keychain (`kSecAttrAccessibleWhenUnlockedThisDeviceOnly`).
 */
@objc(DocBindScreenGuard)
class DocBindModule: NSObject {

    private var captureObserver: NSObjectProtocol?

    @objc
    func isScreenCaptured(_ resolve: @escaping ([String: Any]) -> Void) {
        DispatchQueue.main.async {
            resolve(["isCaptured": UIScreen.main.isCaptured])
        }
    }

    @objc
    func startObservingCaptureChanges(_ onCaptureChanged: @escaping (Bool) -> Void) {
        captureObserver = NotificationCenter.default.addObserver(
            forName: UIScreen.capturedDidChangeNotification,
            object: nil,
            queue: .main
        ) { _ in
            onCaptureChanged(UIScreen.main.isCaptured)
        }
    }

    @objc
    func stopObservingCaptureChanges() {
        if let observer = captureObserver {
            NotificationCenter.default.removeObserver(observer)
            captureObserver = nil
        }
    }

    @objc
    func rsaOaepDecrypt(
        _ alias: String,
        encryptedDekBase64: String,
        resolve: @escaping (String) -> Void,
        reject: @escaping (String, String, Error?) -> Void
    ) {
        guard let tagData = alias.data(using: .utf8),
              let cipherData = Data(base64Encoded: encryptedDekBase64) else {
            reject("INVALID_INPUT", "Invalid alias or Base64 ciphertext", nil)
            return
        }

        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tagData,
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecReturnRef as String: true
        ]

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess, let privateKey = item else {
            reject("KEY_NOT_FOUND", "Private key not found in iOS Keychain", nil)
            return
        }

        var error: Unmanaged<CFError>?
        guard let decryptedData = SecKeyCreateDecryptedData(
            privateKey as! SecKey,
            .rsaEncryptionOAEPSHA256,
            cipherData as CFData,
            &error
        ) as Data? else {
            let err = error?.takeRetainedValue()
            reject("DECRYPT_FAILED", err?.localizedDescription ?? "RSA-OAEP decryption failed", err)
            return
        }

        resolve(decryptedData.base64EncodedString())
    }
}
