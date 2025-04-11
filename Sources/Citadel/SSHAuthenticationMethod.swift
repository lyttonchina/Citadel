import NIO
import NIOSSH
import Crypto

/// Represents an authentication method.
public final class SSHAuthenticationMethod: NIOSSHClientUserAuthenticationDelegate {
    private enum Implementation {
        case custom(NIOSSHClientUserAuthenticationDelegate)
        case user(String, offer: NIOSSHUserAuthenticationOffer.Offer)
    }
    
    private let allImplementations: [Implementation]
    private var implementations: [Implementation]
    
    internal init(
        username: String,
        offer: NIOSSHUserAuthenticationOffer.Offer
    ) {
        self.allImplementations = [.user(username, offer: offer)]
        self.implementations = allImplementations
        
        // 打印初始化信息
        print("创建SSHAuthenticationMethod: 用户名=\(username)")
        switch offer {
        case .password:
            print("认证类型: 密码认证")
        case .hostBased:
            print("认证类型: 主机认证")
        case .privateKey:
            print("认证类型: 私钥认证")
        case .none:
            ()
        }
    }
    
    internal init(
        custom: NIOSSHClientUserAuthenticationDelegate
    ) {
        self.allImplementations = [.custom(custom)]
        self.implementations = allImplementations
    }
    
    /// Creates a password based authentication method.
    /// - Parameters:
    ///   - username: The username to authenticate with.
    ///   - password: The password to authenticate with.
    /// - Returns: A new SSH authentication method.
    public static func passwordBased(username: String, password: String) -> SSHAuthenticationMethod {
        print("创建密码认证: 用户=\(username), 密码长度=\(password.count)")
        return SSHAuthenticationMethod(username: username, offer: .password(.init(password: password)))
    }
    
    /// Creates a public key based authentication method using RSA.
    /// - Parameters: 
    /// - username: The username to authenticate with.
    /// - privateKey: The RSA private key string (PEM or OpenSSH format) or an Insecure.RSA.PrivateKey object.
    /// - publicKey: Optional public key string. If not provided, will be derived from the private key.
    /// - passphrase: Optional passphrase for encrypted keys.
    /// - Returns: An SSH authentication method.
    public static func rsa(
        username: String, 
        privateKey: Any, 
        publicKey: String? = nil, 
        passphrase: String? = nil
    ) throws -> SSHAuthenticationMethod {
        let rsaKey: Insecure.RSA.PrivateKey
        
        if let keyString = privateKey as? String {
            // 打印完整的密钥内容
            print("================ PEM KEY CONTENT BEGIN ================")
            print(keyString)
            print("================ PEM KEY CONTENT END ================")
            
            #if DEBUG
            print("DEBUG: Processing RSA key string of length \(keyString.count)")
            if keyString.hasPrefix("-----BEGIN RSA PRIVATE KEY-----") {
                print("DEBUG: Key appears to be in PEM format")
            } else if keyString.hasPrefix("-----BEGIN OPENSSH PRIVATE KEY-----") {
                print("DEBUG: Key appears to be in OpenSSH format")
            } else {
                print("DEBUG: Key format could not be determined from prefix")
            }
            #endif
            
            do {
                // 处理字符串形式的密钥（自动检测 PEM 或 OpenSSH 格式）
                rsaKey = try Insecure.RSA.PrivateKey(
                    string: keyString, 
                    passphrase: passphrase
                )
                #if DEBUG
                print("DEBUG: Successfully parsed RSA key")
                #endif
            } catch let error as RSAError {
                #if DEBUG
                print("DEBUG: RSA key parsing error: \(error.message)")
                #endif
                throw error
            } catch {
                #if DEBUG
                print("DEBUG: Unexpected error parsing RSA key: \(error)")
                #endif
                throw RSAError(message: "Failed to parse RSA key: \(error.localizedDescription)")
            }
        } else if let key = privateKey as? Insecure.RSA.PrivateKey {
            // 使用已存在的 RSA 私钥对象
            rsaKey = key
            #if DEBUG
            print("DEBUG: Using provided RSA private key object")
            #endif
        } else {
            #if DEBUG
            print("DEBUG: Invalid private key type: \(type(of: privateKey))")
            #endif
            throw SSHClientError.invalidPrivateKeyType
        }
        
        // 如果提供了公钥，可以在这里处理
        if let publicKeyString = publicKey {
            #if DEBUG
            print("DEBUG: Public key string provided (length: \(publicKeyString.count))")
            #endif
        }
        
        return SSHAuthenticationMethod(username: username, offer: .privateKey(.init(privateKey: .init(custom: rsaKey))))
    }
    
    /// Backward compatibility method for PEM format
    /// @deprecated Use rsa(username:keyString:passphrase:) instead
    @available(*, deprecated, message: "Use rsa(username:privateKey:publicKey:passphrase:) instead")
    public static func rsaFromPEM(username: String, pemKey: String, passphrase: String? = nil) throws -> SSHAuthenticationMethod {
        return try rsa(username: username, privateKey: pemKey, passphrase: passphrase)
    }
    
    /// Creates a public key based authentication method.
    /// - Parameters: 
    /// - username: The username to authenticate with.
    /// - privateKey: The private key to authenticate with.
    public static func ed25519(username: String, privateKey: Curve25519.Signing.PrivateKey) -> SSHAuthenticationMethod {
        return SSHAuthenticationMethod(username: username, offer: .privateKey(.init(privateKey: .init(ed25519Key: privateKey))))
    }
    
    /// Creates a public key based authentication method.
    /// - Parameters: 
    /// - username: The username to authenticate with.
    /// - privateKey: The private key to authenticate with.
    public static func p256(username: String, privateKey: P256.Signing.PrivateKey) -> SSHAuthenticationMethod {
        return SSHAuthenticationMethod(username: username, offer: .privateKey(.init(privateKey: .init(p256Key: privateKey))))
    }
    
    /// Creates a public key based authentication method.
    /// - Parameters: 
    /// - username: The username to authenticate with.
    /// - privateKey: The private key to authenticate with.
    public static func p384(username: String, privateKey: P384.Signing.PrivateKey) -> SSHAuthenticationMethod {
        return SSHAuthenticationMethod(username: username, offer: .privateKey(.init(privateKey: .init(p384Key: privateKey))))
    }
    
    /// Creates a public key based authentication method.
    /// - Parameters: 
    /// - username: The username to authenticate with.
    /// - privateKey: The private key to authenticate with.
    public static func p521(username: String, privateKey: P521.Signing.PrivateKey) -> SSHAuthenticationMethod {
        return SSHAuthenticationMethod(username: username, offer: .privateKey(.init(privateKey: .init(p521Key: privateKey))))
    }
    
    public static func custom(_ auth: NIOSSHClientUserAuthenticationDelegate) -> SSHAuthenticationMethod {
        return SSHAuthenticationMethod(custom: auth)
    }
    
    public func nextAuthenticationType(
        availableMethods: NIOSSHAvailableUserAuthenticationMethods,
        nextChallengePromise: EventLoopPromise<NIOSSHUserAuthenticationOffer?>
    ) {
        if implementations.isEmpty {
            nextChallengePromise.fail(SSHClientError.allAuthenticationOptionsFailed)
            return
        }
        
        let implementation = implementations.removeFirst()

        switch implementation {
        case .user(let username, offer: let offer):
            switch offer {
            case .password:
                guard availableMethods.contains(.password) else {
                    nextChallengePromise.fail(SSHClientError.unsupportedPasswordAuthentication)
                    return
                }
            case .hostBased:
                guard availableMethods.contains(.hostBased) else {
                    nextChallengePromise.fail(SSHClientError.unsupportedHostBasedAuthentication)
                    return
                }
            case .privateKey:
                guard availableMethods.contains(.publicKey) else {
                    nextChallengePromise.fail(SSHClientError.unsupportedPrivateKeyAuthentication)
                    return
                }
            case .none:
                ()
            }
            
            nextChallengePromise.succeed(NIOSSHUserAuthenticationOffer(username: username, serviceName: "", offer: offer))
        case .custom(let implementation):
            implementation.nextAuthenticationType(availableMethods: availableMethods, nextChallengePromise: nextChallengePromise)
        }
    }
}
