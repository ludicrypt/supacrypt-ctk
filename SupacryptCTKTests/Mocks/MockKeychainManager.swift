import Foundation
import Security
import CryptoTokenKit
@testable import SupacryptCTK

public class MockKeychainManager: SupacryptKeychainManager {
    
    // MARK: - Mock State
    private var mockKeys: [String: MockKeychainItem] = [:]
    private var mockMetadata: [TKTokenObjectID: SupacryptKeyMetadata] = [:]
    private var shouldFailOperations = false
    private var callCount: [String: Int] = [:]
    
    public struct MockKeychainItem {
        let objectID: TKTokenObjectID
        let keyType: CFString
        let keyClass: SupacryptKeyMetadata.KeyClass
        let keySize: Int
        let label: String
        let applicationTag: Data
        let publicKeyData: Data?
        let attributes: [String: Any]
        let accessControl: SecAccessControl?
    }
    
    // MARK: - Mock Configuration
    
    public override init() {
        super.init()
    }
    
    public func reset() {
        mockKeys.removeAll()
        mockMetadata.removeAll()
        shouldFailOperations = false
        callCount.removeAll()
    }
    
    public func addMockKey(_ item: MockKeychainItem) {
        mockKeys[item.objectID.stringValue] = item
        
        let metadata = SupacryptKeyMetadata(
            keyType: item.keyType,
            keySizeInBits: item.keySize,
            label: item.label,
            keyClass: item.keyClass,
            applicationTag: item.applicationTag,
            publicKeyData: item.publicKeyData,
            canSign: item.keyClass == .privateKey,
            canDecrypt: item.keyClass == .privateKey,
            canDerive: item.keyClass == .privateKey && item.keyType == kSecAttrKeyTypeECSECPrimeRandom,
            canVerify: true,
            canEncrypt: item.keyClass == .publicKey,
            canWrap: false,
            canUnwrap: false
        )
        mockMetadata[item.objectID] = metadata
    }
    
    public func setMockFailure(_ shouldFail: Bool) {
        shouldFailOperations = shouldFail
    }
    
    private func incrementCallCount(for operation: String) {
        callCount[operation, default: 0] += 1
    }
    
    // MARK: - Mock Implementation
    
    public override func keyExists(objectID: TKTokenObjectID) throws -> Bool {
        incrementCallCount(for: "keyExists")
        
        if shouldFailOperations {
            throw MockKeychainError.operationFailed("Key existence check failed")
        }
        
        return mockKeys[objectID.stringValue] != nil
    }
    
    public override func getAllKeyIDs() throws -> [TKTokenObjectID] {
        incrementCallCount(for: "getAllKeyIDs")
        
        if shouldFailOperations {
            throw MockKeychainError.operationFailed("Get all key IDs failed")
        }
        
        return Array(mockKeys.values.map { $0.objectID })
    }
    
    public override func getKeyMetadata(objectID: TKTokenObjectID) throws -> SupacryptKeyMetadata? {
        incrementCallCount(for: "getKeyMetadata")
        
        if shouldFailOperations {
            throw MockKeychainError.operationFailed("Get key metadata failed")
        }
        
        return mockMetadata[objectID]
    }
    
    public override func storeKey(
        keyType: CFString,
        keyClass: SupacryptKeyMetadata.KeyClass,
        keySize: Int,
        label: String,
        applicationTag: Data,
        keyData: Data,
        publicKeyData: Data? = nil,
        accessControl: SecAccessControl? = nil
    ) throws -> TKTokenObjectID {
        incrementCallCount(for: "storeKey")
        
        if shouldFailOperations {
            throw MockKeychainError.operationFailed("Store key failed")
        }
        
        let objectID = TKTokenObjectID(stringValue: "mock-key-\(UUID().uuidString)")
        
        let attributes: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyType as String: keyType,
            kSecAttrKeyClass as String: keyClass.secAttrValue,
            kSecAttrKeySizeInBits as String: keySize,
            kSecAttrLabel as String: label,
            kSecAttrApplicationTag as String: applicationTag,
            kSecValueData as String: keyData,
            kSecAttrTokenID as String: objectID.stringValue
        ]
        
        let mockItem = MockKeychainItem(
            objectID: objectID,
            keyType: keyType,
            keyClass: keyClass,
            keySize: keySize,
            label: label,
            applicationTag: applicationTag,
            publicKeyData: publicKeyData,
            attributes: attributes,
            accessControl: accessControl
        )
        
        addMockKey(mockItem)
        
        return objectID
    }
    
    public override func deleteKey(objectID: TKTokenObjectID) throws {
        incrementCallCount(for: "deleteKey")
        
        if shouldFailOperations {
            throw MockKeychainError.operationFailed("Delete key failed")
        }
        
        guard mockKeys[objectID.stringValue] != nil else {
            throw MockKeychainError.keyNotFound(objectID.stringValue)
        }
        
        mockKeys.removeValue(forKey: objectID.stringValue)
        mockMetadata.removeValue(forKey: objectID)
    }
    
    public override func updateKeyMetadata(
        objectID: TKTokenObjectID,
        metadata: SupacryptKeyMetadata
    ) throws {
        incrementCallCount(for: "updateKeyMetadata")
        
        if shouldFailOperations {
            throw MockKeychainError.operationFailed("Update key metadata failed")
        }
        
        guard mockKeys[objectID.stringValue] != nil else {
            throw MockKeychainError.keyNotFound(objectID.stringValue)
        }
        
        mockMetadata[objectID] = metadata
    }
    
    public override func getKeyData(objectID: TKTokenObjectID) throws -> Data? {
        incrementCallCount(for: "getKeyData")
        
        if shouldFailOperations {
            throw MockKeychainError.operationFailed("Get key data failed")
        }
        
        guard let mockItem = mockKeys[objectID.stringValue] else {
            throw MockKeychainError.keyNotFound(objectID.stringValue)
        }
        
        return mockItem.attributes[kSecValueData as String] as? Data
    }
    
    public override func findKeys(
        keyType: CFString? = nil,
        keyClass: SupacryptKeyMetadata.KeyClass? = nil,
        label: String? = nil,
        applicationTag: Data? = nil
    ) throws -> [TKTokenObjectID] {
        incrementCallCount(for: "findKeys")
        
        if shouldFailOperations {
            throw MockKeychainError.operationFailed("Find keys failed")
        }
        
        let filteredKeys = mockKeys.values.filter { item in
            if let keyType = keyType, item.keyType != keyType {
                return false
            }
            if let keyClass = keyClass, item.keyClass != keyClass {
                return false
            }
            if let label = label, item.label != label {
                return false
            }
            if let applicationTag = applicationTag, item.applicationTag != applicationTag {
                return false
            }
            return true
        }
        
        return filteredKeys.map { $0.objectID }
    }
    
    // MARK: - Mock Helpers
    
    public func getCallCount(for operation: String) -> Int {
        return callCount[operation, default: 0]
    }
    
    public func getTotalCallCount() -> Int {
        return callCount.values.reduce(0, +)
    }
    
    public func getMockKeyCount() -> Int {
        return mockKeys.count
    }
    
    public func getMockKey(objectID: TKTokenObjectID) -> MockKeychainItem? {
        return mockKeys[objectID.stringValue]
    }
    
    public static func createMockRSAKey(
        keySize: Int = 2048,
        label: String = "Test RSA Key",
        keyClass: SupacryptKeyMetadata.KeyClass = .privateKey
    ) -> MockKeychainItem {
        let objectID = TKTokenObjectID(stringValue: "mock-rsa-\(UUID().uuidString)")
        let applicationTag = "test-rsa-key".data(using: .utf8)!
        let keyData = Data(repeating: 0x01, count: keySize / 8)
        let publicKeyData = Data(repeating: 0x02, count: keySize / 8)
        
        let attributes: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass as String: keyClass.secAttrValue,
            kSecAttrKeySizeInBits as String: keySize,
            kSecAttrLabel as String: label,
            kSecAttrApplicationTag as String: applicationTag,
            kSecValueData as String: keyData,
            kSecAttrTokenID as String: objectID.stringValue
        ]
        
        return MockKeychainItem(
            objectID: objectID,
            keyType: kSecAttrKeyTypeRSA,
            keyClass: keyClass,
            keySize: keySize,
            label: label,
            applicationTag: applicationTag,
            publicKeyData: publicKeyData,
            attributes: attributes,
            accessControl: nil
        )
    }
    
    public static func createMockECKey(
        keySize: Int = 256,
        label: String = "Test EC Key",
        keyClass: SupacryptKeyMetadata.KeyClass = .privateKey
    ) -> MockKeychainItem {
        let objectID = TKTokenObjectID(stringValue: "mock-ec-\(UUID().uuidString)")
        let applicationTag = "test-ec-key".data(using: .utf8)!
        let keyData = Data(repeating: 0x03, count: keySize / 8)
        let publicKeyData = Data(repeating: 0x04, count: keySize / 8)
        
        let attributes: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass as String: keyClass.secAttrValue,
            kSecAttrKeySizeInBits as String: keySize,
            kSecAttrLabel as String: label,
            kSecAttrApplicationTag as String: applicationTag,
            kSecValueData as String: keyData,
            kSecAttrTokenID as String: objectID.stringValue
        ]
        
        return MockKeychainItem(
            objectID: objectID,
            keyType: kSecAttrKeyTypeECSECPrimeRandom,
            keyClass: keyClass,
            keySize: keySize,
            label: label,
            applicationTag: applicationTag,
            publicKeyData: publicKeyData,
            attributes: attributes,
            accessControl: nil
        )
    }
}

// MARK: - Mock Errors

public enum MockKeychainError: Error, LocalizedError {
    case operationFailed(String)
    case keyNotFound(String)
    case duplicateKey(String)
    case invalidInput(String)
    
    public var errorDescription: String? {
        switch self {
        case .operationFailed(let message):
            return "Mock keychain operation failed: \(message)"
        case .keyNotFound(let keyID):
            return "Mock key not found: \(keyID)"
        case .duplicateKey(let keyID):
            return "Mock duplicate key: \(keyID)"
        case .invalidInput(let message):
            return "Mock invalid input: \(message)"
        }
    }
}