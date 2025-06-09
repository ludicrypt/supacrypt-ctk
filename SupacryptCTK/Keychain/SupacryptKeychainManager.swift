import Foundation
import Security
import CryptoTokenKit
import OSLog

public class SupacryptKeychainManager {
    private let logger = OSLog(subsystem: "com.supacrypt.ctk", category: "keychain")
    private let accessGroup: String
    
    public init(accessGroup: String = "com.supacrypt.ctk") {
        self.accessGroup = accessGroup
        os_log("SupacryptKeychainManager initialized with access group: %{public}@", 
               log: logger, type: .info, accessGroup)
    }
    
    // MARK: - Key Existence and Metadata
    public func keyExists(objectID: TKTokenObjectID) throws -> Bool {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: objectID.stringValue.data(using: .utf8)!,
            kSecAttrAccessGroup as String: accessGroup,
            kSecReturnRef as String: true
        ]
        
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        
        switch status {
        case errSecSuccess:
            os_log("Key exists for object ID: %{public}@", log: logger, type: .debug, objectID.stringValue)
            return true
        case errSecItemNotFound:
            os_log("Key not found for object ID: %{public}@", log: logger, type: .debug, objectID.stringValue)
            return false
        default:
            os_log("Error checking key existence: %{public}d", log: logger, type: .error, status)
            throw SupacryptError.keychainError(status)
        }
    }
    
    public func getKeyMetadata(objectID: TKTokenObjectID) throws -> SupacryptKeyMetadata? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: objectID.stringValue.data(using: .utf8)!,
            kSecAttrAccessGroup as String: accessGroup,
            kSecReturnAttributes as String: true,
            kSecReturnRef as String: true
        ]
        
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        
        guard status == errSecSuccess,
              let attributes = result as? [String: Any] else {
            if status == errSecItemNotFound {
                return nil
            }
            os_log("Error retrieving key metadata: %{public}d", log: logger, type: .error, status)
            throw SupacryptError.keychainError(status)
        }
        
        return try parseKeyMetadata(from: attributes)
    }
    
    public func getAllKeyIDs() throws -> [TKTokenObjectID] {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrAccessGroup as String: accessGroup,
            kSecReturnAttributes as String: true,
            kSecMatchLimit as String: kSecMatchLimitAll
        ]
        
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        
        guard status == errSecSuccess || status == errSecItemNotFound else {
            os_log("Error retrieving all keys: %{public}d", log: logger, type: .error, status)
            throw SupacryptError.keychainError(status)
        }
        
        guard status == errSecSuccess,
              let items = result as? [[String: Any]] else {
            os_log("No keys found in keychain", log: logger, type: .info)
            return []
        }
        
        var objectIDs: [TKTokenObjectID] = []
        
        for item in items {
            if let tag = item[kSecAttrApplicationTag as String] as? Data,
               let tagString = String(data: tag, encoding: .utf8) {
                let objectID = TKTokenObjectID(stringValue: tagString)
                objectIDs.append(objectID)
            }
        }
        
        os_log("Found %{public}d keys in keychain", log: logger, type: .info, objectIDs.count)
        return objectIDs
    }
    
    // MARK: - Key Storage and Retrieval
    public func storeKeyPair(publicKey: SecKey, 
                           privateKey: SecKey, 
                           metadata: SupacryptKeyMetadata,
                           objectID: TKTokenObjectID) throws {
        os_log("Storing key pair for object ID: %{public}@", log: logger, type: .info, objectID.stringValue)
        
        // Store private key
        try storeKey(privateKey, 
                    metadata: metadata, 
                    objectID: objectID, 
                    keyClass: .privateKey)
        
        // Store public key with modified object ID
        let publicObjectID = TKTokenObjectID(stringValue: objectID.stringValue + "_public")
        var publicMetadata = metadata
        publicMetadata = SupacryptKeyMetadata(
            keyType: metadata.keyType,
            keySizeInBits: metadata.keySizeInBits,
            label: metadata.label + "_public",
            keyClass: .publicKey,
            applicationTag: metadata.applicationTag + Data([0x01]),
            publicKeyData: metadata.publicKeyData,
            canSign: false,
            canDecrypt: false,
            canDerive: metadata.canDerive,
            canVerify: true,
            canEncrypt: true,
            canWrap: metadata.canWrap,
            canUnwrap: false
        )
        
        try storeKey(publicKey, 
                    metadata: publicMetadata, 
                    objectID: publicObjectID, 
                    keyClass: .publicKey)
        
        os_log("Key pair stored successfully", log: logger, type: .info)
    }
    
    private func storeKey(_ key: SecKey, 
                         metadata: SupacryptKeyMetadata, 
                         objectID: TKTokenObjectID, 
                         keyClass: SupacryptKeyMetadata.KeyClass) throws {
        
        var attributes: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecValueRef as String: key,
            kSecAttrApplicationTag as String: metadata.applicationTag,
            kSecAttrAccessGroup as String: accessGroup,
            kSecAttrLabel as String: metadata.label,
            kSecAttrKeyType as String: metadata.keyType,
            kSecAttrKeySizeInBits as String: metadata.keySizeInBits,
            kSecAttrKeyClass as String: keyClass.secAttrValue,
            kSecAttrCanSign as String: metadata.canSign,
            kSecAttrCanDecrypt as String: metadata.canDecrypt,
            kSecAttrCanDerive as String: metadata.canDerive,
            kSecAttrCanVerify as String: metadata.canVerify,
            kSecAttrCanEncrypt as String: metadata.canEncrypt,
            kSecAttrCanWrap as String: metadata.canWrap,
            kSecAttrCanUnwrap as String: metadata.canUnwrap,
            kSecAttrTokenID as String: objectID.stringValue
        ]
        
        // Add access control for private keys
        if keyClass == .privateKey {
            let access = SecAccessControlCreateWithFlags(
                kCFAllocatorDefault,
                kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                [.privateKeyUsage, .applicationPassword],
                nil
            )
            
            if let access = access {
                attributes[kSecAttrAccessControl as String] = access
            }
        }
        
        let status = SecItemAdd(attributes as CFDictionary, nil)
        
        guard status == errSecSuccess || status == errSecDuplicateItem else {
            os_log("Error storing key: %{public}d", log: logger, type: .error, status)
            throw SupacryptError.keychainError(status)
        }
        
        if status == errSecDuplicateItem {
            os_log("Key already exists, updating instead", log: logger, type: .info)
            try updateKey(metadata: metadata, objectID: objectID, keyClass: keyClass)
        }
    }
    
    private func updateKey(metadata: SupacryptKeyMetadata, 
                          objectID: TKTokenObjectID, 
                          keyClass: SupacryptKeyMetadata.KeyClass) throws {
        
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: metadata.applicationTag,
            kSecAttrAccessGroup as String: accessGroup,
            kSecAttrKeyClass as String: keyClass.secAttrValue
        ]
        
        let updates: [String: Any] = [
            kSecAttrLabel as String: metadata.label,
            kSecAttrCanSign as String: metadata.canSign,
            kSecAttrCanDecrypt as String: metadata.canDecrypt,
            kSecAttrCanDerive as String: metadata.canDerive,
            kSecAttrCanVerify as String: metadata.canVerify,
            kSecAttrCanEncrypt as String: metadata.canEncrypt,
            kSecAttrCanWrap as String: metadata.canWrap,
            kSecAttrCanUnwrap as String: metadata.canUnwrap
        ]
        
        let status = SecItemUpdate(query as CFDictionary, updates as CFDictionary)
        
        guard status == errSecSuccess else {
            os_log("Error updating key: %{public}d", log: logger, type: .error, status)
            throw SupacryptError.keychainError(status)
        }
        
        os_log("Key updated successfully", log: logger, type: .info)
    }
    
    public func getSecKey(objectID: TKTokenObjectID, keyClass: SupacryptKeyMetadata.KeyClass) throws -> SecKey? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: objectID.stringValue.data(using: .utf8)!,
            kSecAttrAccessGroup as String: accessGroup,
            kSecAttrKeyClass as String: keyClass.secAttrValue,
            kSecReturnRef as String: true
        ]
        
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        
        guard status == errSecSuccess else {
            if status == errSecItemNotFound {
                return nil
            }
            os_log("Error retrieving SecKey: %{public}d", log: logger, type: .error, status)
            throw SupacryptError.keychainError(status)
        }
        
        return result as! SecKey
    }
    
    // MARK: - Key Deletion
    public func deleteKey(objectID: TKTokenObjectID) throws {
        os_log("Deleting key for object ID: %{public}@", log: logger, type: .info, objectID.stringValue)
        
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: objectID.stringValue.data(using: .utf8)!,
            kSecAttrAccessGroup as String: accessGroup
        ]
        
        let status = SecItemDelete(query as CFDictionary)
        
        guard status == errSecSuccess || status == errSecItemNotFound else {
            os_log("Error deleting key: %{public}d", log: logger, type: .error, status)
            throw SupacryptError.keychainError(status)
        }
        
        os_log("Key deleted successfully", log: logger, type: .info)
    }
    
    // MARK: - Utility Methods
    private func parseKeyMetadata(from attributes: [String: Any]) throws -> SupacryptKeyMetadata {
        guard let keyType = attributes[kSecAttrKeyType as String] as? String,
              let keySizeInBits = attributes[kSecAttrKeySizeInBits as String] as? Int,
              let label = attributes[kSecAttrLabel as String] as? String,
              let keyClassString = attributes[kSecAttrKeyClass as String] as? String,
              let applicationTag = attributes[kSecAttrApplicationTag as String] as? Data else {
            throw SupacryptError.keychainError(errSecParam)
        }
        
        let keyClass: SupacryptKeyMetadata.KeyClass
        if keyClassString == kSecAttrKeyClassPrivate as String {
            keyClass = .privateKey
        } else {
            keyClass = .publicKey
        }
        
        let canSign = attributes[kSecAttrCanSign as String] as? Bool ?? false
        let canDecrypt = attributes[kSecAttrCanDecrypt as String] as? Bool ?? false
        let canDerive = attributes[kSecAttrCanDerive as String] as? Bool ?? false
        let canVerify = attributes[kSecAttrCanVerify as String] as? Bool ?? false
        let canEncrypt = attributes[kSecAttrCanEncrypt as String] as? Bool ?? false
        let canWrap = attributes[kSecAttrCanWrap as String] as? Bool ?? false
        let canUnwrap = attributes[kSecAttrCanUnwrap as String] as? Bool ?? false
        
        return SupacryptKeyMetadata(
            keyType: keyType as CFString,
            keySizeInBits: keySizeInBits,
            label: label,
            keyClass: keyClass,
            applicationTag: applicationTag,
            canSign: canSign,
            canDecrypt: canDecrypt,
            canDerive: canDerive,
            canVerify: canVerify,
            canEncrypt: canEncrypt,
            canWrap: canWrap,
            canUnwrap: canUnwrap
        )
    }
    
    public func generateUniqueObjectID() -> TKTokenObjectID {
        let uuid = UUID().uuidString.lowercased()
        let objectID = TKTokenObjectID(stringValue: "supacrypt_\(uuid)")
        os_log("Generated unique object ID: %{public}@", log: logger, type: .debug, objectID.stringValue)
        return objectID
    }
    
    // MARK: - Keychain Access Group Management
    public func validateAccessGroup() throws -> Bool {
        let testQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccessGroup as String: accessGroup,
            kSecAttrAccount as String: "test_account",
            kSecValueData as String: "test_data".data(using: .utf8)!
        ]
        
        // Try to add a test item
        let addStatus = SecItemAdd(testQuery as CFDictionary, nil)
        
        if addStatus == errSecSuccess || addStatus == errSecDuplicateItem {
            // Clean up test item
            let deleteQuery: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrAccessGroup as String: accessGroup,
                kSecAttrAccount as String: "test_account"
            ]
            SecItemDelete(deleteQuery as CFDictionary)
            
            os_log("Access group validation successful", log: logger, type: .info)
            return true
        } else {
            os_log("Access group validation failed: %{public}d", log: logger, type: .error, addStatus)
            return false
        }
    }
}