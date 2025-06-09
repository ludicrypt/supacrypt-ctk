import Foundation
import CryptoTokenKit
import CryptoKit
import Security
import OSLog

public class SupacryptCryptoOperations {
    private let logger = OSLog(subsystem: "com.supacrypt.ctk", category: "crypto")
    
    public init() {}
    
    // MARK: - Key Generation
    public func generateRSAKeyPair(keySize: Int, 
                                 label: String, 
                                 applicationTag: Data) throws -> (publicKey: SecKey, privateKey: SecKey) {
        os_log("Generating RSA key pair with size %{public}d", log: logger, type: .info, keySize)
        
        let privateKeyAttrs: [String: Any] = [
            kSecAttrIsPermanent as String: true,
            kSecAttrApplicationTag as String: applicationTag,
            kSecAttrLabel as String: "\(label)_private"
        ]
        
        let publicKeyAttrs: [String: Any] = [
            kSecAttrIsPermanent as String: true,
            kSecAttrApplicationTag as String: applicationTag + Data([0x01]),
            kSecAttrLabel as String: "\(label)_public"
        ]
        
        let keyPairAttrs: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits as String: keySize,
            kSecPrivateKeyAttrs as String: privateKeyAttrs,
            kSecPublicKeyAttrs as String: publicKeyAttrs
        ]
        
        var publicKey: SecKey?
        var privateKey: SecKey?
        
        let status = SecKeyGeneratePair(keyPairAttrs as CFDictionary, &publicKey, &privateKey)
        
        guard status == errSecSuccess,
              let pubKey = publicKey,
              let privKey = privateKey else {
            os_log("RSA key generation failed with status: %{public}d", log: logger, type: .error, status)
            throw SupacryptError.keyGenerationFailed(status: status)
        }
        
        os_log("RSA key pair generated successfully", log: logger, type: .info)
        return (publicKey: pubKey, privateKey: privKey)
    }
    
    public func generateECKeyPair(curve: SupacryptECCurve, 
                                label: String, 
                                applicationTag: Data) throws -> (publicKey: SecKey, privateKey: SecKey) {
        os_log("Generating EC key pair with curve %{public}@", log: logger, type: .info, curve.rawValue)
        
        let privateKeyAttrs: [String: Any] = [
            kSecAttrIsPermanent as String: true,
            kSecAttrApplicationTag as String: applicationTag,
            kSecAttrLabel as String: "\(label)_private"
        ]
        
        let publicKeyAttrs: [String: Any] = [
            kSecAttrIsPermanent as String: true,
            kSecAttrApplicationTag as String: applicationTag + Data([0x01]),
            kSecAttrLabel as String: "\(label)_public"
        ]
        
        let keyPairAttrs: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: curve.keySizeInBits,
            kSecPrivateKeyAttrs as String: privateKeyAttrs,
            kSecPublicKeyAttrs as String: publicKeyAttrs
        ]
        
        var publicKey: SecKey?
        var privateKey: SecKey?
        
        let status = SecKeyGeneratePair(keyPairAttrs as CFDictionary, &publicKey, &privateKey)
        
        guard status == errSecSuccess,
              let pubKey = publicKey,
              let privKey = privateKey else {
            os_log("EC key generation failed with status: %{public}d", log: logger, type: .error, status)
            throw SupacryptError.keyGenerationFailed(status: status)
        }
        
        os_log("EC key pair generated successfully", log: logger, type: .info)
        return (publicKey: pubKey, privateKey: privKey)
    }
    
    // MARK: - Signing Operations
    public func signData(_ data: Data, 
                        with privateKey: SecKey, 
                        algorithm: SupacryptSigningAlgorithm) throws -> Data {
        os_log("Signing data with algorithm %{public}@", log: logger, type: .info, algorithm.rawValue)
        
        let secAlgorithm = try algorithm.toSecKeyAlgorithm()
        
        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(
            privateKey,
            secAlgorithm,
            data as CFData,
            &error
        ) else {
            let cfError = error?.takeRetainedValue()
            os_log("Signing failed: %{public}@", log: logger, type: .error, 
                   cfError?.localizedDescription ?? "Unknown error")
            throw SupacryptError.signingFailed(error: cfError)
        }
        
        os_log("Data signed successfully", log: logger, type: .info)
        return signature as Data
    }
    
    public func verifySignature(_ signature: Data, 
                               for data: Data, 
                               with publicKey: SecKey, 
                               algorithm: SupacryptSigningAlgorithm) throws -> Bool {
        os_log("Verifying signature with algorithm %{public}@", log: logger, type: .info, algorithm.rawValue)
        
        let secAlgorithm = try algorithm.toSecKeyAlgorithm()
        
        var error: Unmanaged<CFError>?
        let isValid = SecKeyVerifySignature(
            publicKey,
            secAlgorithm,
            data as CFData,
            signature as CFData,
            &error
        )
        
        if let cfError = error?.takeRetainedValue() {
            os_log("Signature verification failed: %{public}@", log: logger, type: .error, 
                   cfError.localizedDescription)
            throw SupacryptError.verificationFailed(error: cfError)
        }
        
        os_log("Signature verification result: %{public}@", log: logger, type: .info, isValid.description)
        return isValid
    }
    
    // MARK: - Encryption/Decryption Operations
    public func encryptData(_ data: Data, 
                           with publicKey: SecKey, 
                           algorithm: SupacryptEncryptionAlgorithm) throws -> Data {
        os_log("Encrypting data with algorithm %{public}@", log: logger, type: .info, algorithm.rawValue)
        
        let secAlgorithm = try algorithm.toSecKeyAlgorithm()
        
        var error: Unmanaged<CFError>?
        guard let encryptedData = SecKeyCreateEncryptedData(
            publicKey,
            secAlgorithm,
            data as CFData,
            &error
        ) else {
            let cfError = error?.takeRetainedValue()
            os_log("Encryption failed: %{public}@", log: logger, type: .error, 
                   cfError?.localizedDescription ?? "Unknown error")
            throw SupacryptError.encryptionFailed(error: cfError)
        }
        
        os_log("Data encrypted successfully", log: logger, type: .info)
        return encryptedData as Data
    }
    
    public func decryptData(_ encryptedData: Data, 
                           with privateKey: SecKey, 
                           algorithm: SupacryptEncryptionAlgorithm) throws -> Data {
        os_log("Decrypting data with algorithm %{public}@", log: logger, type: .info, algorithm.rawValue)
        
        let secAlgorithm = try algorithm.toSecKeyAlgorithm()
        
        var error: Unmanaged<CFError>?
        guard let decryptedData = SecKeyCreateDecryptedData(
            privateKey,
            secAlgorithm,
            encryptedData as CFData,
            &error
        ) else {
            let cfError = error?.takeRetainedValue()
            os_log("Decryption failed: %{public}@", log: logger, type: .error, 
                   cfError?.localizedDescription ?? "Unknown error")
            throw SupacryptError.decryptionFailed(error: cfError)
        }
        
        os_log("Data decrypted successfully", log: logger, type: .info)
        return decryptedData as Data
    }
    
    // MARK: - Key Exchange Operations
    public func performKeyExchange(with publicKey: SecKey, 
                                 using privateKey: SecKey, 
                                 algorithm: SupacryptKeyExchangeAlgorithm) throws -> Data {
        os_log("Performing key exchange with algorithm %{public}@", log: logger, type: .info, algorithm.rawValue)
        
        let secAlgorithm = try algorithm.toSecKeyAlgorithm()
        
        var error: Unmanaged<CFError>?
        guard let sharedSecret = SecKeyCopyKeyExchangeResult(
            privateKey,
            secAlgorithm,
            publicKey,
            [:] as CFDictionary,
            &error
        ) else {
            let cfError = error?.takeRetainedValue()
            os_log("Key exchange failed: %{public}@", log: logger, type: .error, 
                   cfError?.localizedDescription ?? "Unknown error")
            throw SupacryptError.keyExchangeFailed(error: cfError)
        }
        
        os_log("Key exchange completed successfully", log: logger, type: .info)
        return sharedSecret as Data
    }
}

// MARK: - Supporting Types
public enum SupacryptECCurve: String {
    case p256 = "P-256"
    case p384 = "P-384"
    case p521 = "P-521"
    
    var keySizeInBits: Int {
        switch self {
        case .p256: return 256
        case .p384: return 384
        case .p521: return 521
        }
    }
}

public enum SupacryptSigningAlgorithm: String {
    case rsaSignatureMessagePKCS1v15SHA256 = "RSA-PKCS1v15-SHA256"
    case rsaSignatureMessagePKCS1v15SHA384 = "RSA-PKCS1v15-SHA384"
    case rsaSignatureMessagePKCS1v15SHA512 = "RSA-PKCS1v15-SHA512"
    case rsaSignatureMessagePSSsha256 = "RSA-PSS-SHA256"
    case rsaSignatureMessagePSSsha384 = "RSA-PSS-SHA384"
    case rsaSignatureMessagePSSsha512 = "RSA-PSS-SHA512"
    case ecdsaSignatureMessageX962SHA256 = "ECDSA-SHA256"
    case ecdsaSignatureMessageX962SHA384 = "ECDSA-SHA384"
    case ecdsaSignatureMessageX962SHA512 = "ECDSA-SHA512"
    
    func toSecKeyAlgorithm() throws -> SecKeyAlgorithm {
        switch self {
        case .rsaSignatureMessagePKCS1v15SHA256:
            return .rsaSignatureMessagePKCS1v15SHA256
        case .rsaSignatureMessagePKCS1v15SHA384:
            return .rsaSignatureMessagePKCS1v15SHA384
        case .rsaSignatureMessagePKCS1v15SHA512:
            return .rsaSignatureMessagePKCS1v15SHA512
        case .rsaSignatureMessagePSSsha256:
            return .rsaSignatureMessagePSSsha256
        case .rsaSignatureMessagePSSsha384:
            return .rsaSignatureMessagePSSsha384
        case .rsaSignatureMessagePSSsha512:
            return .rsaSignatureMessagePSSsha512
        case .ecdsaSignatureMessageX962SHA256:
            return .ecdsaSignatureMessageX962SHA256
        case .ecdsaSignatureMessageX962SHA384:
            return .ecdsaSignatureMessageX962SHA384
        case .ecdsaSignatureMessageX962SHA512:
            return .ecdsaSignatureMessageX962SHA512
        }
    }
}

public enum SupacryptEncryptionAlgorithm: String {
    case rsaEncryptionOAEPSHA256 = "RSA-OAEP-SHA256"
    case rsaEncryptionOAEPSHA384 = "RSA-OAEP-SHA384"
    case rsaEncryptionOAEPSHA512 = "RSA-OAEP-SHA512"
    case rsaEncryptionPKCS1 = "RSA-PKCS1"
    
    func toSecKeyAlgorithm() throws -> SecKeyAlgorithm {
        switch self {
        case .rsaEncryptionOAEPSHA256:
            return .rsaEncryptionOAEPSHA256
        case .rsaEncryptionOAEPSHA384:
            return .rsaEncryptionOAEPSHA384
        case .rsaEncryptionOAEPSHA512:
            return .rsaEncryptionOAEPSHA512
        case .rsaEncryptionPKCS1:
            return .rsaEncryptionPKCS1
        }
    }
}

public enum SupacryptKeyExchangeAlgorithm: String {
    case ecdhKeyExchangeStandard = "ECDH-Standard"
    case ecdhKeyExchangeCofactor = "ECDH-Cofactor"
    
    func toSecKeyAlgorithm() throws -> SecKeyAlgorithm {
        switch self {
        case .ecdhKeyExchangeStandard:
            return .ecdhKeyExchangeStandard
        case .ecdhKeyExchangeCofactor:
            return .ecdhKeyExchangeCofactor
        }
    }
}

// MARK: - Error Types
public enum SupacryptError: Error {
    case keyGenerationFailed(status: OSStatus)
    case signingFailed(error: CFError?)
    case verificationFailed(error: CFError?)
    case encryptionFailed(error: CFError?)
    case decryptionFailed(error: CFError?)
    case keyExchangeFailed(error: CFError?)
    case invalidAlgorithm(String)
    case keychainError(OSStatus)
    case grpcError(String)
}

extension SupacryptError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .keyGenerationFailed(let status):
            return "Key generation failed with status: \(status)"
        case .signingFailed(let error):
            return "Signing failed: \(error?.localizedDescription ?? "Unknown error")"
        case .verificationFailed(let error):
            return "Verification failed: \(error?.localizedDescription ?? "Unknown error")"
        case .encryptionFailed(let error):
            return "Encryption failed: \(error?.localizedDescription ?? "Unknown error")"
        case .decryptionFailed(let error):
            return "Decryption failed: \(error?.localizedDescription ?? "Unknown error")"
        case .keyExchangeFailed(let error):
            return "Key exchange failed: \(error?.localizedDescription ?? "Unknown error")"
        case .invalidAlgorithm(let algorithm):
            return "Invalid algorithm: \(algorithm)"
        case .keychainError(let status):
            return "Keychain error: \(status)"
        case .grpcError(let message):
            return "gRPC error: \(message)"
        }
    }
}