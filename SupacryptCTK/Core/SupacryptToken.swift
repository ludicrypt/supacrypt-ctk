import Foundation
import CryptoTokenKit
import OSLog
import Logging

public class SupacryptToken: TKToken {
    private let logger = Logger(label: "com.supacrypt.ctk.token")
    private let osLogger = OSLog(subsystem: "com.supacrypt.ctk", category: "token")
    private let driver: SupacryptTokenDriver
    private let grpcClient: SupacryptGRPCClient
    
    init(tokenID: TKTokenID, 
         configuration: TKTokenConfiguration, 
         driver: SupacryptTokenDriver) throws {
        self.driver = driver
        self.grpcClient = try SupacryptGRPCClient()
        
        super.init(tokenID: tokenID, configuration: configuration)
        
        os_log("SupacryptToken initialized for ID: %{public}@", 
               log: osLogger, type: .info, tokenID.stringValue)
        logger.info("SupacryptToken initialized for ID: \(tokenID.stringValue)")
    }
    
    deinit {
        os_log("SupacryptToken deinitialized", log: osLogger, type: .info)
        logger.info("SupacryptToken deinitialized")
    }
    
    public override func createSession(format: TKTokenSessionFormat) throws -> TKTokenSession {
        os_log("Creating session with format: %{public}@", 
               log: osLogger, type: .info, String(describing: format))
        logger.info("Creating session with format: \(String(describing: format))")
        
        let session = SupacryptTokenSession(
            token: self,
            format: format,
            grpcClient: grpcClient
        )
        
        os_log("Session created successfully", log: osLogger, type: .info)
        logger.info("Session created successfully")
        
        return session
    }
    
    public override func supports(operation: TKTokenOperation) -> Bool {
        switch operation {
        case .readData, .signData, .decryptData, .performKeyExchange:
            return true
        default:
            return false
        }
    }
    
    public override var tokenClass: TKTokenClass {
        return .hardwareToken
    }
    
    public override var tokenInfo: [String: Any] {
        return [
            kSecAttrTokenID as String: tokenID.stringValue,
            kSecAttrLabel as String: "Supacrypt Token",
            "Manufacturer": "Supacrypt",
            "Model": "CTK Provider v1.0",
            "SerialNumber": tokenID.stringValue,
            "FirmwareVersion": "1.0.0"
        ]
    }
}