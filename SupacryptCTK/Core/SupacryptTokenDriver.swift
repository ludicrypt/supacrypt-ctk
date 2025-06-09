import Foundation
import CryptoTokenKit
import OSLog
import Logging

@objc(SupacryptTokenDriver)
public class SupacryptTokenDriver: TKTokenDriver {
    private let logger = Logger(label: "com.supacrypt.ctk.driver")
    private let osLogger = OSLog(subsystem: "com.supacrypt.ctk", category: "driver")
    
    public override init() {
        super.init()
        os_log("SupacryptTokenDriver initialized", log: osLogger, type: .info)
        logger.info("SupacryptTokenDriver initialized")
    }
    
    deinit {
        os_log("SupacryptTokenDriver deinitialized", log: osLogger, type: .info)
        logger.info("SupacryptTokenDriver deinitialized")
    }
    
    public override func createToken(forTokenID tokenID: TKTokenID, 
                                   configuration: TKTokenConfiguration) throws -> TKToken {
        os_log("Creating token for ID: %{public}@", log: osLogger, type: .info, tokenID.stringValue)
        logger.info("Creating token for ID: \(tokenID.stringValue)")
        
        let token = try SupacryptToken(
            tokenID: tokenID,
            configuration: configuration,
            driver: self
        )
        
        os_log("Token created successfully for ID: %{public}@", log: osLogger, type: .info, tokenID.stringValue)
        logger.info("Token created successfully for ID: \(tokenID.stringValue)")
        
        return token
    }
    
    public override func terminate() {
        os_log("SupacryptTokenDriver terminating", log: osLogger, type: .info)
        logger.info("SupacryptTokenDriver terminating")
        super.terminate()
    }
}

extension SupacryptTokenDriver {
    public static let shared = SupacryptTokenDriver()
    
    static func getTokenIDs() -> [TKTokenID] {
        return [TKTokenID(stringValue: "com.supacrypt.ctk.token")]
    }
    
    static func getTokenConfiguration(for tokenID: TKTokenID) -> TKTokenConfiguration {
        let config = TKTokenConfiguration()
        config.instanceID = tokenID.stringValue
        config.keychainAccessGroup = "com.supacrypt.ctk"
        return config
    }
}