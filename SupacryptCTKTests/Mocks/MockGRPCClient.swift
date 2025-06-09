import Foundation
import GRPC
import NIO
@testable import SupacryptCTK

public class MockGRPCClient: SupacryptGRPCClient {
    
    // MARK: - Mock State
    var shouldFailConnection = false
    var shouldFailOperations = false
    var responseDelay: TimeInterval = 0.0
    var mockKeys: [String: MockKeyData] = [:]
    var callCount: [String: Int] = [:]
    
    public struct MockKeyData {
        let keyID: String
        let keyType: CFString
        let keySize: Int
        let publicKey: Data
        let canSign: Bool
        let canDecrypt: Bool
        let canDerive: Bool
    }
    
    // MARK: - Mock Configuration
    public override init(configuration: GRPCConfiguration = .default) throws {
        // Don't call super.init to avoid creating real gRPC connections
        // This is a mock implementation
    }
    
    public func reset() {
        shouldFailConnection = false
        shouldFailOperations = false
        responseDelay = 0.0
        mockKeys.removeAll()
        callCount.removeAll()
    }
    
    public func addMockKey(_ keyData: MockKeyData) {
        mockKeys[keyData.keyID] = keyData
    }
    
    public func setMockFailure(connection: Bool = false, operations: Bool = false) {
        shouldFailConnection = connection
        shouldFailOperations = operations
    }
    
    private func incrementCallCount(for operation: String) {
        callCount[operation, default: 0] += 1
    }
    
    private func simulateDelay() async throws {
        if responseDelay > 0 {
            try await Task.sleep(nanoseconds: UInt64(responseDelay * 1_000_000_000))
        }
    }
    
    // MARK: - Mock Implementation
    
    public override func testConnection() async throws -> Bool {
        incrementCallCount(for: "testConnection")
        try await simulateDelay()
        
        if shouldFailConnection {
            throw MockError.connectionFailed
        }
        
        return true
    }
    
    public override func generateKey(request: Supacrypt_V1_GenerateKeyRequest) async throws -> Supacrypt_V1_GenerateKeyResponse {
        incrementCallCount(for: "generateKey")
        try await simulateDelay()
        
        if shouldFailOperations {
            throw MockError.operationFailed("Key generation failed")
        }
        
        var response = Supacrypt_V1_GenerateKeyResponse()
        response.version = 1
        
        var keyMetadata = Supacrypt_V1_KeyMetadata()
        keyMetadata.keyID = "mock-key-\(UUID().uuidString)"
        keyMetadata.name = request.name
        keyMetadata.keyType = request.keyType
        keyMetadata.keySize = Int32(request.keySize)
        keyMetadata.publicKey = Data(repeating: 0x42, count: 256) // Mock public key
        keyMetadata.createdAt = Supacrypt_V1_Timestamp()
        keyMetadata.createdAt.seconds = Int64(Date().timeIntervalSince1970)
        
        response.key = keyMetadata
        
        // Add to mock storage
        let mockKey = MockKeyData(
            keyID: keyMetadata.keyID,
            keyType: kSecAttrKeyTypeRSA,
            keySize: Int(request.keySize),
            publicKey: keyMetadata.publicKey,
            canSign: true,
            canDecrypt: true,
            canDerive: false
        )
        addMockKey(mockKey)
        
        return response
    }
    
    public override func getKey(request: Supacrypt_V1_GetKeyRequest) async throws -> Supacrypt_V1_GetKeyResponse {
        incrementCallCount(for: "getKey")
        try await simulateDelay()
        
        if shouldFailOperations {
            throw MockError.operationFailed("Key retrieval failed")
        }
        
        guard let mockKey = mockKeys[request.keyID] else {
            throw MockError.keyNotFound(request.keyID)
        }
        
        var response = Supacrypt_V1_GetKeyResponse()
        response.version = 1
        
        var keyMetadata = Supacrypt_V1_KeyMetadata()
        keyMetadata.keyID = mockKey.keyID
        keyMetadata.keyType = mockKey.keyType as String
        keyMetadata.keySize = Int32(mockKey.keySize)
        keyMetadata.publicKey = mockKey.publicKey
        keyMetadata.createdAt = Supacrypt_V1_Timestamp()
        keyMetadata.createdAt.seconds = Int64(Date().timeIntervalSince1970)
        
        response.key = keyMetadata
        
        return response
    }
    
    public override func listKeys(request: Supacrypt_V1_ListKeysRequest) async throws -> Supacrypt_V1_ListKeysResponse {
        incrementCallCount(for: "listKeys")
        try await simulateDelay()
        
        if shouldFailOperations {
            throw MockError.operationFailed("Key listing failed")
        }
        
        var response = Supacrypt_V1_ListKeysResponse()
        response.version = 1
        
        let keys = Array(mockKeys.values.prefix(Int(request.pageSize)))
        response.keys = keys.map { mockKey in
            var keyMetadata = Supacrypt_V1_KeyMetadata()
            keyMetadata.keyID = mockKey.keyID
            keyMetadata.keyType = mockKey.keyType as String
            keyMetadata.keySize = Int32(mockKey.keySize)
            keyMetadata.publicKey = mockKey.publicKey
            keyMetadata.createdAt = Supacrypt_V1_Timestamp()
            keyMetadata.createdAt.seconds = Int64(Date().timeIntervalSince1970)
            return keyMetadata
        }
        
        response.totalCount = Int32(mockKeys.count)
        response.hasMore = mockKeys.count > Int(request.pageSize)
        
        return response
    }
    
    public override func deleteKey(request: Supacrypt_V1_DeleteKeyRequest) async throws -> Supacrypt_V1_DeleteKeyResponse {
        incrementCallCount(for: "deleteKey")
        try await simulateDelay()
        
        if shouldFailOperations {
            throw MockError.operationFailed("Key deletion failed")
        }
        
        guard mockKeys[request.keyID] != nil else {
            throw MockError.keyNotFound(request.keyID)
        }
        
        mockKeys.removeValue(forKey: request.keyID)
        
        var response = Supacrypt_V1_DeleteKeyResponse()
        response.version = 1
        response.success = true
        
        return response
    }
    
    public override func signData(request: Supacrypt_V1_SignDataRequest) async throws -> Data {
        incrementCallCount(for: "signData")
        try await simulateDelay()
        
        if shouldFailOperations {
            throw MockError.operationFailed("Signing failed")
        }
        
        guard let mockKey = mockKeys[request.keyID] else {
            throw MockError.keyNotFound(request.keyID)
        }
        
        guard mockKey.canSign else {
            throw MockError.operationNotSupported("Key cannot sign")
        }
        
        // Return a mock signature (would be actual signature in real implementation)
        return Data(repeating: 0x99, count: mockKey.keySize / 8)
    }
    
    public override func verifySignature(request: Supacrypt_V1_VerifySignatureRequest) async throws -> Bool {
        incrementCallCount(for: "verifySignature")
        try await simulateDelay()
        
        if shouldFailOperations {
            throw MockError.operationFailed("Verification failed")
        }
        
        guard mockKeys[request.keyID] != nil else {
            throw MockError.keyNotFound(request.keyID)
        }
        
        // Mock verification logic - in real implementation would verify actual signature
        return request.signature.count > 0
    }
    
    public override func encryptData(request: Supacrypt_V1_EncryptDataRequest) async throws -> Data {
        incrementCallCount(for: "encryptData")
        try await simulateDelay()
        
        if shouldFailOperations {
            throw MockError.operationFailed("Encryption failed")
        }
        
        guard mockKeys[request.keyID] != nil else {
            throw MockError.keyNotFound(request.keyID)
        }
        
        // Return mock encrypted data
        return request.plaintext + Data(repeating: 0xAA, count: 16) // Simulate padding
    }
    
    public override func decryptData(request: Supacrypt_V1_DecryptDataRequest) async throws -> Data {
        incrementCallCount(for: "decryptData")
        try await simulateDelay()
        
        if shouldFailOperations {
            throw MockError.operationFailed("Decryption failed")
        }
        
        guard let mockKey = mockKeys[request.keyID] else {
            throw MockError.keyNotFound(request.keyID)
        }
        
        guard mockKey.canDecrypt else {
            throw MockError.operationNotSupported("Key cannot decrypt")
        }
        
        // Mock decryption - remove the padding we added during encryption
        let paddingSize = 16
        guard request.ciphertext.count > paddingSize else {
            throw MockError.operationFailed("Invalid ciphertext")
        }
        
        return request.ciphertext.dropLast(paddingSize)
    }
    
    // MARK: - Mock Helpers
    
    public func getCallCount(for operation: String) -> Int {
        return callCount[operation, default: 0]
    }
    
    public func getTotalCallCount() -> Int {
        return callCount.values.reduce(0, +)
    }
}

// MARK: - Mock Errors

public enum MockError: Error, LocalizedError {
    case connectionFailed
    case operationFailed(String)
    case keyNotFound(String)
    case operationNotSupported(String)
    
    public var errorDescription: String? {
        switch self {
        case .connectionFailed:
            return "Mock connection failed"
        case .operationFailed(let message):
            return "Mock operation failed: \(message)"
        case .keyNotFound(let keyID):
            return "Mock key not found: \(keyID)"
        case .operationNotSupported(let message):
            return "Mock operation not supported: \(message)"
        }
    }
}