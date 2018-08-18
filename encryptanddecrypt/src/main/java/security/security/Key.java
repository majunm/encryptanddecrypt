package security.security;


import security.util.AesEncryptionUtil;
import security.util.MD5Utils;

public class Key {
    /**
     * 密钥
     */
    public static String KEY = "$75k!xxH&$EhQLmv"; // 密钥
    /**
     * 密钥偏移
     */
    public static final String KEYIV = MD5Utils.md5(KEY).substring(0, 16); // 密钥偏移

    public static void main(String[] args) {
        String encrypt = AesEncryptionUtil.encrypt("natural_aes");
        String decrypt = AesEncryptionUtil.decrypt(AesEncryptionUtil.encrypt("natural_aes"));
        System.out.println("#加密串#" + encrypt);
        System.out.println("#解密串#" + decrypt);
    }
}
