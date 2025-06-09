import Foundation
import CryptoTokenKit
import OSLog
import Logging
import Security

public class SupacryptTokenSession: TKTokenSession {
    private let logger = Logger(label: "com.supacrypt.ctk.session")
    private let osLogger = OSLog(subsystem: "com.supacrypt.ctk", category: "session")
    private let grpcClient: SupacryptGRPCClient
    private let keychainManager: SupacryptKeychainManager
    
    init(token: SupacryptToken, format: TKTokenSessionFormat, grpcClient: SupacryptGRPCClient) {
        self.grpcClient = grpcClient
        self.keychainManager = SupacryptKeychainManager()
        
        super.init(token: token, format: format)
        
        os_log("SupacryptTokenSession initialized", log: osLogger, type: .info)
        logger.info("SupacryptTokenSession initialized")
    }
    
    deinit {
        os_log("SupacryptTokenSession deinitialized", log: osLogger, type: .info)
        logger.info("SupacryptTokenSession deinitialized")
    }
    
    public override func objectExists(objectID: TKTokenObjectID) -> Bool {
        do {
            let exists = try keychainManager.keyExists(objectID: objectID)
            os_log("Object exists check for %{public}@: %{public}@", 
                   log: osLogger, type: .debug, objectID.stringValue, exists.description)
            return exists
        } catch {
            os_log("Error checking object existence: %{public}@", 
                   log: osLogger, type: .error, error.localizedDescription)
            return false
        }
    }
    
    public override func objectIDs() throws -> [TKTokenObjectID] {
        os_log("Retrieving object IDs", log: osLogger, type: .debug)
        
        do {
            let objectIDs = try keychainManager.getAllKeyIDs()
            os_log("Found %{public}d objects", log: osLogger, type: .info, objectIDs.count)
            return objectIDs
        } catch {
            os_log("Error retrieving object IDs: %{public}@", 
                   log: osLogger, type: .error, error.localizedDescription)
            throw error
        }
    }
    
    public override func objects(forObjectIDs objectIDs: [TKTokenObjectID]) throws -> [TKTokenObjectID: TKTokenObject] {
        os_log("Creating objects for %{public}d IDs", log: osLogger, type: .debug, objectIDs.count)
        
        var objects: [TKTokenObjectID: TKTokenObject] = [:]
        
        for objectID in objectIDs {
            do {
                if let keyObject = try createKeyObject(for: objectID) {
                    objects[objectID] = keyObject
                }
            } catch {
                os_log("Error creating object for ID %{public}@: %{public}@", 
                       log: osLogger, type: .error, objectID.stringValue, error.localizedDescription)
                throw error
            }
        }
        
        os_log("Created %{public}d objects", log: osLogger, type: .info, objects.count)
        return objects
    }
    
    public override func sign(_ data: Data, 
                            keyObjectID: TKTokenObjectID, 
                            algorithm: TKTokenKeyAlgorithm) async throws -> Data {
        os_log("Signing data with key %{public}@ using algorithm %{public}@", 
               log: osLogger, type: .info, keyObjectID.stringValue, String(describing: algorithm))
        
        do {
            let signature = try await performSignOperation(
                data: data,
                keyObjectID: keyObjectID,
                algorithm: algorithm
            )
            
            os_log("Signing completed successfully", log: osLogger, type: .info)
            return signature
        } catch {
            os_log("Signing failed: %{public}@", log: osLogger, type: .error, error.localizedDescription)
            throw error
        }
    }
    
    public override func decrypt(_ data: Data, 
                               keyObjectID: TKTokenObjectID, 
                               algorithm: TKTokenKeyAlgorithm) async throws -> Data {
        os_log("Decrypting data with key %{public}@ using algorithm %{public}@", 
               log: osLogger, type: .info, keyObjectID.stringValue, String(describing: algorithm))
        
        do {
            let decryptedData = try await performDecryptOperation(
                data: data,
                keyObjectID: keyObjectID,
                algorithm: algorithm
            )
            
            os_log("Decryption completed successfully", log: osLogger, type: .info)
            return decryptedData
        } catch {
            os_log("Decryption failed: %{public}@", log: osLogger, type: .error, error.localizedDescription)
            throw error
        }
    }
    
    public override func performKeyExchange(with publicKey: Data, 
                                          keyObjectID: TKTokenObjectID, 
                                          algorithm: TKTokenKeyAlgorithm, 
                                          parameters: TKTokenKeyExchangeParameters) async throws -> Data {
        os_log("Performing key exchange with key %{public}@", 
               log: osLogger, type: .info, keyObjectID.stringValue)
        
        do {
            let sharedSecret = try await performKeyExchangeOperation(
                publicKey: publicKey,
                keyObjectID: keyObjectID,
                algorithm: algorithm,
                parameters: parameters
            )
            
            os_log("Key exchange completed successfully", log: osLogger, type: .info)
            return sharedSecret
        } catch {
            os_log("Key exchange failed: %{public}@", log: osLogger, type: .error, error.localizedDescription)
            throw error
        }
    }
}

// MARK: - Private Methods
extension SupacryptTokenSession {
    private func createKeyObject(for objectID: TKTokenObjectID) throws -> TKTokenObject? {
        guard let keyMetadata = try keychainManager.getKeyMetadata(objectID: objectID) else {
            return nil
        }
        
        return SupacryptKeyObject(
            objectID: objectID,
            metadata: keyMetadata
        )
    }
    
    private func performSignOperation(data: Data, 
                                    keyObjectID: TKTokenObjectID, 
                                    algorithm: TKTokenKeyAlgorithm) async throws -> Data {
        
        let request = try SupacryptRequestBuilder.buildSignRequest(
            data: data,
            keyID: keyObjectID.stringValue,
            algorithm: algorithm
        )
        
        return try await grpcClient.signData(request: request)
    }
    
    private func performDecryptOperation(data: Data, 
                                       keyObjectID: TKTokenObjectID, 
                                       algorithm: TKTokenKeyAlgorithm) async throws -> Data {
        
        let request = try SupacryptRequestBuilder.buildDecryptRequest(
            data: data,
            keyID: keyObjectID.stringValue,
            algorithm: algorithm
        )
        
        return try await grpcClient.decryptData(request: request)
    }
    
    private func performKeyExchangeOperation(publicKey: Data, 
                                           keyObjectID: TKTokenObjectID, 
                                           algorithm: TKTokenKeyAlgorithm,
                                           parameters: TKTokenKeyExchangeParameters) async throws -> Data {
        
        // Key exchange would be implemented here based on the algorithm
        // For ECDH, this would involve generating a shared secret
        throw TKError(.corruptedData) // Placeholder for now
    }
}