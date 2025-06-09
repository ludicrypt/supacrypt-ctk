import Foundation
import CryptoTokenKit
@testable import SupacryptCTK

// MARK: - Mock Token Driver

public class MockSupacryptTokenDriver: SupacryptTokenDriver {
    
    private var mockTokens: [TKTokenID: MockSupacryptToken] = [:]
    private var shouldFailCreation = false
    private var creationCallCount = 0
    
    public func setMockFailure(_ shouldFail: Bool) {
        shouldFailCreation = shouldFail
    }
    
    public func getCreationCallCount() -> Int {
        return creationCallCount
    }
    
    public func getMockToken(for tokenID: TKTokenID) -> MockSupacryptToken? {
        return mockTokens[tokenID]
    }
    
    public override func createToken(forTokenID tokenID: TKTokenID, 
                                   configuration: TKTokenConfiguration) throws -> TKToken {
        creationCallCount += 1
        
        if shouldFailCreation {
            throw MockCTKError.tokenCreationFailed
        }
        
        let mockToken = MockSupacryptToken(
            tokenID: tokenID,
            configuration: configuration,
            driver: self
        )
        
        mockTokens[tokenID] = mockToken
        return mockToken
    }
    
    public func reset() {
        mockTokens.removeAll()
        shouldFailCreation = false
        creationCallCount = 0
    }
}

// MARK: - Mock Token

public class MockSupacryptToken: SupacryptToken {
    
    private var mockSessions: [TKTokenSessionFormat: MockSupacryptTokenSession] = [:]
    private var shouldFailSessionCreation = false
    private var sessionCreationCallCount = 0
    private var mockGRPCClient: MockGRPCClient?
    
    public init(tokenID: TKTokenID, 
               configuration: TKTokenConfiguration, 
               driver: MockSupacryptTokenDriver) {
        // Initialize with mock gRPC client to avoid real network connections
        do {
            mockGRPCClient = try MockGRPCClient()
        } catch {
            // Handle mock client creation error
        }
        
        super.init()
        self.tokenID = tokenID
    }
    
    public func setMockFailure(sessionCreation: Bool) {
        shouldFailSessionCreation = sessionCreation
    }
    
    public func getSessionCreationCallCount() -> Int {
        return sessionCreationCallCount
    }
    
    public func getMockSession(for format: TKTokenSessionFormat) -> MockSupacryptTokenSession? {
        return mockSessions[format]
    }
    
    public override func createSession(format: TKTokenSessionFormat) throws -> TKTokenSession {
        sessionCreationCallCount += 1
        
        if shouldFailSessionCreation {
            throw MockCTKError.sessionCreationFailed
        }
        
        let mockSession = MockSupacryptTokenSession(
            token: self,
            format: format,
            grpcClient: mockGRPCClient ?? MockGRPCClient()
        )
        
        mockSessions[format] = mockSession
        return mockSession
    }
    
    public override func supports(operation: TKTokenOperation) -> Bool {
        // Mock implementation supports all operations for testing
        switch operation {
        case .readData, .signData, .decryptData, .performKeyExchange:
            return true
        default:
            return false
        }
    }
    
    public func reset() {
        mockSessions.removeAll()
        shouldFailSessionCreation = false
        sessionCreationCallCount = 0
        mockGRPCClient?.reset()
    }
}

// MARK: - Mock Token Session

public class MockSupacryptTokenSession: SupacryptTokenSession {
    
    private var mockObjects: [TKTokenObjectID: MockSupacryptKeyObject] = [:]
    private var shouldFailOperations = false
    private var operationCallCounts: [String: Int] = [:]
    private var mockKeychainManager: MockKeychainManager
    private var mockGRPCClient: MockGRPCClient
    
    public init(token: MockSupacryptToken, 
               format: TKTokenSessionFormat, 
               grpcClient: MockGRPCClient) {
        self.mockKeychainManager = MockKeychainManager()
        self.mockGRPCClient = grpcClient
        
        super.init()
        self.token = token
        self.format = format
    }
    
    public func setMockFailure(_ shouldFail: Bool) {
        shouldFailOperations = shouldFail
        mockKeychainManager.setMockFailure(shouldFail)
        mockGRPCClient.setMockFailure(operations: shouldFail)
    }
    
    public func addMockObject(_ object: MockSupacryptKeyObject) {
        mockObjects[object.objectID] = object
        
        // Also add to mock keychain
        let mockKeychainItem = MockKeychainManager.MockKeychainItem(
            objectID: object.objectID,
            keyType: kSecAttrKeyTypeRSA, // Default for testing
            keyClass: .privateKey,
            keySize: 2048,
            label: "Mock Key",
            applicationTag: Data("mock".utf8),
            publicKeyData: Data(repeating: 0x42, count: 256),
            attributes: [:],
            accessControl: nil
        )
        mockKeychainManager.addMockKey(mockKeychainItem)
    }
    
    public func getOperationCallCount(for operation: String) -> Int {
        return operationCallCounts[operation, default: 0]
    }
    
    private func incrementCallCount(for operation: String) {
        operationCallCounts[operation, default: 0] += 1
    }
    
    public override func objectExists(objectID: TKTokenObjectID) -> Bool {
        incrementCallCount(for: "objectExists")
        
        if shouldFailOperations {
            return false
        }
        
        return mockObjects[objectID] != nil
    }
    
    public override func objectIDs() throws -> [TKTokenObjectID] {
        incrementCallCount(for: "objectIDs")
        
        if shouldFailOperations {
            throw MockCTKError.operationFailed("objectIDs failed")
        }
        
        return Array(mockObjects.keys)
    }
    
    public override func objects(forObjectIDs objectIDs: [TKTokenObjectID]) throws -> [TKTokenObjectID: TKTokenObject] {
        incrementCallCount(for: "objects")
        
        if shouldFailOperations {
            throw MockCTKError.operationFailed("objects failed")
        }
        
        var result: [TKTokenObjectID: TKTokenObject] = [:]
        
        for objectID in objectIDs {
            if let mockObject = mockObjects[objectID] {
                result[objectID] = mockObject
            }
        }
        
        return result
    }
    
    public override func sign(_ data: Data, 
                            keyObjectID: TKTokenObjectID, 
                            algorithm: TKTokenKeyAlgorithm) async throws -> Data {
        incrementCallCount(for: "sign")
        
        if shouldFailOperations {
            throw MockCTKError.operationFailed("sign failed")
        }
        
        guard mockObjects[keyObjectID] != nil else {
            throw MockCTKError.keyNotFound(keyObjectID.stringValue)
        }
        
        // Return mock signature
        return Data(repeating: 0x99, count: 256)
    }
    
    public override func decrypt(_ data: Data, 
                               keyObjectID: TKTokenObjectID, 
                               algorithm: TKTokenKeyAlgorithm) async throws -> Data {
        incrementCallCount(for: "decrypt")
        
        if shouldFailOperations {
            throw MockCTKError.operationFailed("decrypt failed")
        }
        
        guard mockObjects[keyObjectID] != nil else {
            throw MockCTKError.keyNotFound(keyObjectID.stringValue)
        }
        
        // Return mock decrypted data (remove some bytes to simulate decryption)
        return data.dropLast(16)
    }
    
    public override func performKeyExchange(with publicKey: Data, 
                                          keyObjectID: TKTokenObjectID, 
                                          algorithm: TKTokenKeyAlgorithm, 
                                          parameters: TKTokenKeyExchangeParameters) async throws -> Data {
        incrementCallCount(for: "performKeyExchange")
        
        if shouldFailOperations {
            throw MockCTKError.operationFailed("performKeyExchange failed")
        }
        
        guard mockObjects[keyObjectID] != nil else {
            throw MockCTKError.keyNotFound(keyObjectID.stringValue)
        }
        
        // Return mock shared secret
        return Data(repeating: 0xCC, count: 32)
    }
    
    public func reset() {
        mockObjects.removeAll()
        shouldFailOperations = false
        operationCallCounts.removeAll()
        mockKeychainManager.reset()
        mockGRPCClient.reset()
    }
    
    public func getMockKeychainManager() -> MockKeychainManager {
        return mockKeychainManager
    }
    
    public func getMockGRPCClient() -> MockGRPCClient {
        return mockGRPCClient
    }
}

// MARK: - Mock Key Object

public class MockSupacryptKeyObject: SupacryptKeyObject {
    
    private var mockMetadata: SupacryptKeyMetadata
    private var mockOperations: [TKTokenOperation]
    
    public init(objectID: TKTokenObjectID, 
               metadata: SupacryptKeyMetadata? = nil,
               operations: [TKTokenOperation] = [.signData, .decryptData]) {
        
        self.mockMetadata = metadata ?? SupacryptKeyMetadata(
            keyType: kSecAttrKeyTypeRSA,
            keySizeInBits: 2048,
            label: "Mock Key",
            keyClass: .privateKey,
            applicationTag: Data("mock".utf8),
            publicKeyData: Data(repeating: 0x42, count: 256),
            canSign: true,
            canDecrypt: true,
            canDerive: false,
            canVerify: true,
            canEncrypt: false,
            canWrap: false,
            canUnwrap: false
        )
        
        self.mockOperations = operations
        
        super.init(objectID: objectID, metadata: self.mockMetadata)
    }
    
    public override var operations: [TKTokenOperation] {
        return mockOperations
    }
    
    public func setMockOperations(_ operations: [TKTokenOperation]) {
        mockOperations = operations
    }
    
    public func updateMockMetadata(_ metadata: SupacryptKeyMetadata) {
        mockMetadata = metadata
    }
}

// MARK: - Mock Errors

public enum MockCTKError: Error, LocalizedError {
    case tokenCreationFailed
    case sessionCreationFailed
    case operationFailed(String)
    case keyNotFound(String)
    case invalidConfiguration
    
    public var errorDescription: String? {
        switch self {
        case .tokenCreationFailed:
            return "Mock token creation failed"
        case .sessionCreationFailed:
            return "Mock session creation failed"
        case .operationFailed(let message):
            return "Mock operation failed: \(message)"
        case .keyNotFound(let keyID):
            return "Mock key not found: \(keyID)"
        case .invalidConfiguration:
            return "Mock invalid configuration"
        }
    }
}