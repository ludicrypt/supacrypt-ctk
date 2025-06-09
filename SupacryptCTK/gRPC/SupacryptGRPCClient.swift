import Foundation
import GRPC
import NIO
import NIOSSL
import OSLog
import Logging

public class SupacryptGRPCClient {
    private let logger = Logger(label: "com.supacrypt.ctk.grpc")
    private let osLogger = OSLog(subsystem: "com.supacrypt.ctk", category: "grpc")
    private let eventLoopGroup: EventLoopGroup
    private let channel: GRPCChannel
    private let client: Supacrypt_V1_SupacryptServiceNIOClient
    private let configuration: GRPCConfiguration
    
    public init(configuration: GRPCConfiguration = .default) throws {
        self.configuration = configuration
        self.eventLoopGroup = MultiThreadedEventLoopGroup(numberOfThreads: 2)
        
        // Create channel with TLS configuration
        let channelBuilder = ClientConnection.insecure(group: eventLoopGroup)
            .connect(host: configuration.host, port: configuration.port)
        
        self.channel = channelBuilder
        self.client = Supacrypt_V1_SupacryptServiceNIOClient(
            channel: channel,
            defaultCallOptions: configuration.callOptions
        )
        
        os_log("SupacryptGRPCClient initialized for %{public}@:%{public}d", 
               log: osLogger, type: .info, configuration.host, configuration.port)
        logger.info("SupacryptGRPCClient initialized for \(configuration.host):\(configuration.port)")
    }
    
    deinit {
        do {
            try channel.close().wait()
            try eventLoopGroup.syncShutdownGracefully()
        } catch {
            os_log("Error during gRPC client shutdown: %{public}@", 
                   log: osLogger, type: .error, error.localizedDescription)
        }
    }
    
    // MARK: - Key Management Operations
    public func generateKey(request: Supacrypt_V1_GenerateKeyRequest) async throws -> Supacrypt_V1_GenerateKeyResponse {
        os_log("Generating key with name: %{public}@", log: osLogger, type: .info, request.name)
        
        do {
            let response = try await client.generateKey(request).response.get()
            os_log("Key generation completed successfully", log: osLogger, type: .info)
            return response
        } catch {
            os_log("Key generation failed: %{public}@", log: osLogger, type: .error, error.localizedDescription)
            throw SupacryptError.grpcError("Key generation failed: \(error.localizedDescription)")
        }
    }
    
    public func getKey(request: Supacrypt_V1_GetKeyRequest) async throws -> Supacrypt_V1_GetKeyResponse {
        os_log("Getting key with ID: %{public}@", log: osLogger, type: .info, request.keyID)
        
        do {
            let response = try await client.getKey(request).response.get()
            os_log("Key retrieval completed successfully", log: osLogger, type: .info)
            return response
        } catch {
            os_log("Key retrieval failed: %{public}@", log: osLogger, type: .error, error.localizedDescription)
            throw SupacryptError.grpcError("Key retrieval failed: \(error.localizedDescription)")
        }
    }
    
    public func listKeys(request: Supacrypt_V1_ListKeysRequest) async throws -> Supacrypt_V1_ListKeysResponse {
        os_log("Listing keys with filter: %{public}@", log: osLogger, type: .info, request.filter)
        
        do {
            let response = try await client.listKeys(request).response.get()
            os_log("Key listing completed successfully", log: osLogger, type: .info)
            return response
        } catch {
            os_log("Key listing failed: %{public}@", log: osLogger, type: .error, error.localizedDescription)
            throw SupacryptError.grpcError("Key listing failed: \(error.localizedDescription)")
        }
    }
    
    public func deleteKey(request: Supacrypt_V1_DeleteKeyRequest) async throws -> Supacrypt_V1_DeleteKeyResponse {
        os_log("Deleting key with ID: %{public}@", log: osLogger, type: .info, request.keyID)
        
        do {
            let response = try await client.deleteKey(request).response.get()
            os_log("Key deletion completed successfully", log: osLogger, type: .info)
            return response
        } catch {
            os_log("Key deletion failed: %{public}@", log: osLogger, type: .error, error.localizedDescription)
            throw SupacryptError.grpcError("Key deletion failed: \(error.localizedDescription)")
        }
    }
    
    // MARK: - Cryptographic Operations
    public func signData(request: Supacrypt_V1_SignDataRequest) async throws -> Data {
        os_log("Signing data with key ID: %{public}@", log: osLogger, type: .info, request.keyID)
        
        do {
            let response = try await client.signData(request).response.get()
            
            switch response.result {
            case .success(let success):
                os_log("Data signing completed successfully", log: osLogger, type: .info)
                return success.signature
            case .error(let error):
                os_log("Data signing failed: %{public}@", log: osLogger, type: .error, error.message)
                throw SupacryptError.grpcError("Signing failed: \(error.message)")
            case .none:
                throw SupacryptError.grpcError("Invalid response format")
            }
        } catch {
            os_log("Data signing failed: %{public}@", log: osLogger, type: .error, error.localizedDescription)
            throw SupacryptError.grpcError("Signing failed: \(error.localizedDescription)")
        }
    }
    
    public func verifySignature(request: Supacrypt_V1_VerifySignatureRequest) async throws -> Bool {
        os_log("Verifying signature with key ID: %{public}@", log: osLogger, type: .info, request.keyID)
        
        do {
            let response = try await client.verifySignature(request).response.get()
            
            switch response.result {
            case .success(let success):
                os_log("Signature verification completed: %{public}@", log: osLogger, type: .info, success.isValid.description)
                return success.isValid
            case .error(let error):
                os_log("Signature verification failed: %{public}@", log: osLogger, type: .error, error.message)
                throw SupacryptError.grpcError("Verification failed: \(error.message)")
            case .none:
                throw SupacryptError.grpcError("Invalid response format")
            }
        } catch {
            os_log("Signature verification failed: %{public}@", log: osLogger, type: .error, error.localizedDescription)
            throw SupacryptError.grpcError("Verification failed: \(error.localizedDescription)")
        }
    }
    
    public func encryptData(request: Supacrypt_V1_EncryptDataRequest) async throws -> Data {
        os_log("Encrypting data with key ID: %{public}@", log: osLogger, type: .info, request.keyID)
        
        do {
            let response = try await client.encryptData(request).response.get()
            
            switch response.result {
            case .success(let success):
                os_log("Data encryption completed successfully", log: osLogger, type: .info)
                return success.ciphertext
            case .error(let error):
                os_log("Data encryption failed: %{public}@", log: osLogger, type: .error, error.message)
                throw SupacryptError.grpcError("Encryption failed: \(error.message)")
            case .none:
                throw SupacryptError.grpcError("Invalid response format")
            }
        } catch {
            os_log("Data encryption failed: %{public}@", log: osLogger, type: .error, error.localizedDescription)
            throw SupacryptError.grpcError("Encryption failed: \(error.localizedDescription)")
        }
    }
    
    public func decryptData(request: Supacrypt_V1_DecryptDataRequest) async throws -> Data {
        os_log("Decrypting data with key ID: %{public}@", log: osLogger, type: .info, request.keyID)
        
        do {
            let response = try await client.decryptData(request).response.get()
            
            switch response.result {
            case .success(let success):
                os_log("Data decryption completed successfully", log: osLogger, type: .info)
                return success.plaintext
            case .error(let error):
                os_log("Data decryption failed: %{public}@", log: osLogger, type: .error, error.message)
                throw SupacryptError.grpcError("Decryption failed: \(error.message)")
            case .none:
                throw SupacryptError.grpcError("Invalid response format")
            }
        } catch {
            os_log("Data decryption failed: %{public}@", log: osLogger, type: .error, error.localizedDescription)
            throw SupacryptError.grpcError("Decryption failed: \(error.localizedDescription)")
        }
    }
    
    // MARK: - Connection Management
    public func testConnection() async throws -> Bool {
        os_log("Testing gRPC connection", log: osLogger, type: .info)
        
        do {
            var request = Supacrypt_V1_ListKeysRequest()
            request.version = 1
            request.pageSize = 1
            
            _ = try await client.listKeys(request).response.get()
            os_log("Connection test successful", log: osLogger, type: .info)
            return true
        } catch {
            os_log("Connection test failed: %{public}@", log: osLogger, type: .error, error.localizedDescription)
            return false
        }
    }
}

// MARK: - Configuration
public struct GRPCConfiguration {
    let host: String
    let port: Int
    let callOptions: CallOptions
    let tlsConfiguration: TLSConfiguration?
    
    public init(host: String = "localhost",
                port: Int = 50051,
                timeout: TimeInterval = 30.0,
                tlsConfiguration: TLSConfiguration? = nil) {
        self.host = host
        self.port = port
        self.tlsConfiguration = tlsConfiguration
        
        var callOptions = CallOptions()
        callOptions.timeLimit = .timeout(.seconds(Int64(timeout)))
        self.callOptions = callOptions
    }
    
    public static let `default` = GRPCConfiguration()
}

// MARK: - Request Builders
public struct SupacryptRequestBuilder {
    public static func buildSignRequest(data: Data, 
                                       keyID: String, 
                                       algorithm: TKTokenKeyAlgorithm) throws -> Supacrypt_V1_SignDataRequest {
        var request = Supacrypt_V1_SignDataRequest()
        request.version = 1
        request.keyID = keyID
        request.data = data
        request.isPrehashed = false
        
        // Convert TKTokenKeyAlgorithm to Supacrypt signing parameters
        request.parameters = try convertToSigningParameters(algorithm)
        
        return request
    }
    
    public static func buildDecryptRequest(data: Data, 
                                         keyID: String, 
                                         algorithm: TKTokenKeyAlgorithm) throws -> Supacrypt_V1_DecryptDataRequest {
        var request = Supacrypt_V1_DecryptDataRequest()
        request.version = 1
        request.keyID = keyID
        request.ciphertext = data
        
        // Convert TKTokenKeyAlgorithm to Supacrypt encryption parameters
        request.parameters = try convertToEncryptionParameters(algorithm)
        
        return request
    }
    
    private static func convertToSigningParameters(_ algorithm: TKTokenKeyAlgorithm) throws -> Supacrypt_V1_SigningParameters {
        var params = Supacrypt_V1_SigningParameters()
        
        switch algorithm {
        case .rsaSignaturePKCS1SHA256:
            params.hashAlgorithm = .sha256
            var rsaParams = Supacrypt_V1_RSASigningParameters()
            rsaParams.paddingScheme = .pkcs1
            params.rsaParams = rsaParams
        case .rsaSignaturePKCS1SHA384:
            params.hashAlgorithm = .sha384
            var rsaParams = Supacrypt_V1_RSASigningParameters()
            rsaParams.paddingScheme = .pkcs1
            params.rsaParams = rsaParams
        case .rsaSignaturePKCS1SHA512:
            params.hashAlgorithm = .sha512
            var rsaParams = Supacrypt_V1_RSASigningParameters()
            rsaParams.paddingScheme = .pkcs1
            params.rsaParams = rsaParams
        case .ecdsaSignatureDigestX962SHA256:
            params.hashAlgorithm = .sha256
            params.eccParams = Supacrypt_V1_ECCSigningParameters()
        case .ecdsaSignatureDigestX962SHA384:
            params.hashAlgorithm = .sha384
            params.eccParams = Supacrypt_V1_ECCSigningParameters()
        case .ecdsaSignatureDigestX962SHA512:
            params.hashAlgorithm = .sha512
            params.eccParams = Supacrypt_V1_ECCSigningParameters()
        default:
            throw SupacryptError.invalidAlgorithm("Unsupported signing algorithm: \(algorithm)")
        }
        
        return params
    }
    
    private static func convertToEncryptionParameters(_ algorithm: TKTokenKeyAlgorithm) throws -> Supacrypt_V1_EncryptionParameters {
        var params = Supacrypt_V1_EncryptionParameters()
        
        switch algorithm {
        case .rsaEncryptionOAEPSHA256:
            var rsaParams = Supacrypt_V1_RSAEncryptionParameters()
            rsaParams.paddingScheme = .oaep
            rsaParams.oaepHash = .sha256
            params.rsaParams = rsaParams
        case .rsaEncryptionOAEPSHA384:
            var rsaParams = Supacrypt_V1_RSAEncryptionParameters()
            rsaParams.paddingScheme = .oaep
            rsaParams.oaepHash = .sha384
            params.rsaParams = rsaParams
        case .rsaEncryptionOAEPSHA512:
            var rsaParams = Supacrypt_V1_RSAEncryptionParameters()
            rsaParams.paddingScheme = .oaep
            rsaParams.oaepHash = .sha512
            params.rsaParams = rsaParams
        case .rsaEncryptionPKCS1:
            var rsaParams = Supacrypt_V1_RSAEncryptionParameters()
            rsaParams.paddingScheme = .pkcs1
            params.rsaParams = rsaParams
        default:
            throw SupacryptError.invalidAlgorithm("Unsupported encryption algorithm: \(algorithm)")
        }
        
        return params
    }
}