import Foundation
import CCryptoBoringSSL

/// Utility class for working with PEM (Privacy Enhanced Mail) format
public struct PEM {
    private static let privateKeyPrefix = "-----BEGIN RSA PRIVATE KEY-----"
    private static let privateKeySuffix = "-----END RSA PRIVATE KEY-----"
    private static let publicKeyPrefix = "-----BEGIN PUBLIC KEY-----"
    private static let publicKeySuffix = "-----END PUBLIC KEY-----"
    
    /// Extracts the base64 content from a PEM formatted string
    /// - Parameter pemString: The PEM string with headers and footers
    /// - Returns: The base64 decoded data or nil if invalid
    public static func extractDERData(from pemString: String) throws -> Data {
        // 添加更直接的提取方式 - 直接从BEGIN和END标记之间提取内容
        if pemString.contains(privateKeyPrefix) && pemString.contains(privateKeySuffix) {
            print("尝试直接提取PEM内容")
            let components = pemString.components(separatedBy: privateKeyPrefix)
            if components.count > 1 {
                let afterBegin = components[1]
                let endComponents = afterBegin.components(separatedBy: privateKeySuffix)
                if endComponents.count > 0 {
                    let base64Content = endComponents[0].trimmingCharacters(in: .whitespacesAndNewlines)
                    // 移除所有空白字符
                    let cleanedBase64 = base64Content.replacingOccurrences(of: "\\s+", with: "", options: .regularExpression)
                    if let data = Data(base64Encoded: cleanedBase64, options: .ignoreUnknownCharacters) {
                        print("成功直接提取PEM内容，长度: \(data.count)")
                        return data
                    } else {
                        print("直接提取失败，尝试标准提取方式")
                    }
                }
            }
        }
        
        // 标准Scanner提取方式
        let scanner = Scanner(string: pemString)
        var base64: String?
        
        if pemString.contains(privateKeyPrefix) && pemString.contains(privateKeySuffix) {
            guard scanner.scanUpToString(privateKeyPrefix) != nil else {
                throw RSAError.invalidPem
            }
            guard scanner.scanString(privateKeyPrefix) != nil else {
                throw RSAError.invalidPem
            }
            base64 = scanner.scanUpToString(privateKeySuffix)
        } else if pemString.contains(publicKeyPrefix) && pemString.contains(publicKeySuffix) {
            guard scanner.scanUpToString(publicKeyPrefix) != nil else {
                throw RSAError.invalidPem
            }
            guard scanner.scanString(publicKeyPrefix) != nil else {
                throw RSAError.invalidPem
            }
            base64 = scanner.scanUpToString(publicKeySuffix)
        } else {
            throw RSAError.invalidPem
        }
        
        guard let base64Content = base64?.trimmingCharacters(in: .whitespacesAndNewlines) else {
            throw RSAError.invalidPem
        }
        
        guard let data = Data(base64Encoded: base64Content, options: .ignoreUnknownCharacters) else {
            throw RSAError.invalidPem
        }
        
        return data
    }
    
    /// Reads a private key from a PEM string
    /// - Parameters:
    ///   - pemString: The PEM encoded private key
    ///   - passphrase: Optional passphrase for encrypted keys
    /// - Returns: A BoringSSL RSA key structure
    public static func readPrivateKey(from pemString: String, passphrase: String? = nil) throws -> UnsafeMutablePointer<RSA> {
        print("使用直接BIO方法读取PEM")
        
        // 尝试通过临时文件读取PEM
        do {
            let tempDir = FileManager.default.temporaryDirectory
            let tempFile = tempDir.appendingPathComponent("temp_key_\(UUID().uuidString).pem")
            
            // 确保PEM内容格式化正确
            var formattedPEM = pemString.trimmingCharacters(in: .whitespacesAndNewlines)
            if !formattedPEM.hasSuffix("\n") {
                formattedPEM += "\n"
            }
            
            // 写入临时文件
            try formattedPEM.write(to: tempFile, atomically: true, encoding: .utf8)
            print("已将PEM写入临时文件: \(tempFile.path)")
            
            // 从文件中读取
            guard let bio = CCryptoBoringSSL_BIO_new_file(tempFile.path, "r") else {
                try? FileManager.default.removeItem(at: tempFile)
                throw RSAError.pkcs1Error
            }
            defer { 
                CCryptoBoringSSL_BIO_free(bio)
                try? FileManager.default.removeItem(at: tempFile)
            }
            
            let rsa = CCryptoBoringSSL_RSA_new()!
            
            let result: UnsafeMutablePointer<RSA>?
            
            if let passphrase = passphrase, !passphrase.isEmpty {
                let cPassphrase = passphrase.withCString { cs in
                    return UnsafeMutablePointer(mutating: cs)
                }
                result = CCryptoBoringSSL_PEM_read_bio_RSAPrivateKey(bio, nil, nil, cPassphrase)
            } else {
                result = CCryptoBoringSSL_PEM_read_bio_RSAPrivateKey(bio, nil, nil, nil)
            }
            
            guard let rsaKey = result else {
                CCryptoBoringSSL_RSA_free(rsa)
                
                // 检查并打印错误信息
                var errorCode: UInt32 = 0
                let errorString = CCryptoBoringSSL_ERR_error_string(CCryptoBoringSSL_ERR_get_error(), nil)
                let errorMessage = String(cString: errorString!)
                print("BoringSSL Error (文件方法): \(errorMessage)")
                
                throw RSAError.pkcs1Error
            }
            
            print("从临时文件成功读取PEM!")
            return rsaKey
        } catch {
            print("临时文件方法失败: \(error)")
            
            // 如果临时文件方法失败，尝试原始的内存方法
            // 将PEM字符串直接传递给BIO，不做任何预处理
            guard let bio = pemString.withCString({ cstr -> UnsafeMutablePointer<BIO>? in
                return CCryptoBoringSSL_BIO_new_mem_buf(cstr, Int32(pemString.count))
            }) else {
                throw RSAError.invalidPem
            }
            defer { CCryptoBoringSSL_BIO_free(bio) }
            
            let rsa = CCryptoBoringSSL_RSA_new()!
            
            let result: UnsafeMutablePointer<RSA>?
            
            if let passphrase = passphrase, !passphrase.isEmpty {
                let cPassphrase = passphrase.withCString { cs in
                    return UnsafeMutablePointer(mutating: cs)
                }
                result = CCryptoBoringSSL_PEM_read_bio_RSAPrivateKey(bio, nil, nil, cPassphrase)
            } else {
                result = CCryptoBoringSSL_PEM_read_bio_RSAPrivateKey(bio, nil, nil, nil)
            }
            
            guard let rsaKey = result else {
                CCryptoBoringSSL_RSA_free(rsa)
                
                // 检查并打印错误信息
                var errorCode: UInt32 = 0
                let errorString = CCryptoBoringSSL_ERR_error_string(CCryptoBoringSSL_ERR_get_error(), nil)
                let errorMessage = String(cString: errorString!)
                print("BoringSSL Error (内存方法): \(errorMessage)")
                
                throw RSAError.pkcs1Error
            }
            
            print("使用内存方法成功读取PEM!")
            return rsaKey
        }
    }
    
    /// 规范化PEM格式，处理各种不规范的输入
    private static func normalizePEM(_ pemString: String) throws -> String {
        // 打印原始PEM内容的详细信息
        print("================ PEM NORMALIZATION ANALYSIS BEGIN ================")
        print("PEM内容长度: \(pemString.count)")
        print("PEM内容是否包含BEGIN标记: \(pemString.contains(privateKeyPrefix))")
        print("PEM内容是否包含END标记: \(pemString.contains(privateKeySuffix))")
        
        if pemString.contains(privateKeyPrefix) {
            let components = pemString.components(separatedBy: privateKeyPrefix)
            print("BEGIN前的内容长度: \(components.first?.count ?? 0)")
            if components.count > 1 {
                print("BEGIN后的内容是否包含END标记: \(components[1].contains(privateKeySuffix))")
                let endComponents = components[1].components(separatedBy: privateKeySuffix)
                print("BEGIN和END之间的内容长度: \(endComponents.first?.count ?? 0)")
                print("END后的内容长度: \(endComponents.last?.count ?? 0)")
                
                // 检查内容是否是有效的Base64
                if let base64Content = endComponents.first?.trimmingCharacters(in: .whitespacesAndNewlines) {
                    let cleanedBase64 = base64Content.replacingOccurrences(of: "\\s+", with: "", options: .regularExpression)
                    print("Base64内容长度: \(cleanedBase64.count)")
                    print("是否是有效的Base64: \(Data(base64Encoded: cleanedBase64, options: .ignoreUnknownCharacters) != nil)")
                }
            }
        }
        
        // 显示ASCII代码，有助于发现不可见字符
        print("ASCII代码 (前50个字符):")
        for (i, char) in pemString.prefix(50).enumerated() {
            let ascii = char.asciiValue ?? 0
            print("[\(i)] '\(char)' = \(ascii)")
        }
        
        print("================ PEM NORMALIZATION ANALYSIS END ================")
        
        // 移除任何可能的BOM标记和多余空白
        var normalizedPEM = pemString.trimmingCharacters(in: .whitespacesAndNewlines)
        
        // 检查是否包含RSA私钥标识
        guard normalizedPEM.contains(privateKeyPrefix) && normalizedPEM.contains(privateKeySuffix) else {
            throw RSAError.invalidPem
        }
        
        // 提取开始标记和结束标记之间的内容，重新构建标准格式
        let scanner = Scanner(string: normalizedPEM)
        guard scanner.scanUpToString(privateKeyPrefix) != nil else {
            throw RSAError.invalidPem
        }
        guard scanner.scanString(privateKeyPrefix) != nil else {
            throw RSAError.invalidPem
        }
        
        var base64Content = scanner.scanUpToString(privateKeySuffix) ?? ""
        
        // 清理Base64内容（移除所有空白字符）
        base64Content = base64Content.replacingOccurrences(of: "\\s+", with: "", options: .regularExpression)
        
        // 确保Base64内容不为空
        guard !base64Content.isEmpty else {
            throw RSAError.invalidPem
        }
        
        // 按每行64个字符重新格式化Base64内容
        var formattedBase64 = ""
        var index = 0
        
        while index < base64Content.count {
            let endIndex = min(index + 64, base64Content.count)
            let range = base64Content.index(base64Content.startIndex, offsetBy: index)..<base64Content.index(base64Content.startIndex, offsetBy: endIndex)
            formattedBase64 += String(base64Content[range]) + "\n"
            index = endIndex
        }
        
        // 构建格式正确的PEM
        return privateKeyPrefix + "\n" + formattedBase64 + privateKeySuffix
    }
    
    /// Reads a public key from a PEM string
    /// - Parameter pemString: The PEM encoded public key
    /// - Returns: A BoringSSL RSA key structure with only public components
    public static func readPublicKey(from pemString: String) throws -> UnsafeMutablePointer<RSA> {
        let data = try extractDERData(from: pemString)
        
        let bio = CCryptoBoringSSL_BIO_new_mem_buf(data.withUnsafeBytes { $0.baseAddress }, Int32(data.count))
        defer { CCryptoBoringSSL_BIO_free(bio) }
        
        let rsa = CCryptoBoringSSL_RSA_new()!
        
        guard let rsaKey = CCryptoBoringSSL_PEM_read_bio_RSA_PUBKEY(bio, nil, nil, nil) else {
            CCryptoBoringSSL_RSA_free(rsa)
            throw RSAError.pkcs1Error
        }
        
        return rsaKey
    }
} 