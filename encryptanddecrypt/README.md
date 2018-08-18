```
Key.KEY = "密钥"; // 和服务器的约定,剩下的调用即可
System.out.println("AES加密后="+AesEncryptionUtil.encrypt("123456")+
                "\nAES解密后="+AesEncryptionUtil.decrypt(AesEncryptionUtil.encrypt("123456"))+
                "RSA加密后="+ Rsa.encryptByPublic("123456")+
                "\nRSA解密后="+Rsa.decryptByPublic(Rsa.encryptByPublic("123456"))
        );
```