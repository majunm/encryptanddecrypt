package security.config;

import android.util.Base64;
import android.util.Log;


import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;

import security.security.util.RSAUtils;

/**
 * 公钥加密
 * 私钥加密
 * 公钥解密
 * 私钥解密
 * ----->>>> 公钥加密，服务器私钥解密
 * 公钥用来公开并加密，私钥用来保留解密，且不可互换。
 */
public class Rsa {
    // public static final String RSA_PUBLICE = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDJ4/3VqHevhEUwMvmkY/DizPUF/s2lhyXHp1AhZhpzMjFUMGFIppJyHhcg3/r1jTHo+RJOjiT4D0g4yameVcp3ELmhyQArde4+gAG9762Zk4eDU+MM4AtOG7jSQk23BFWtYYEtwjXhGCX+L37sMqDdDJd6dLnKD+ghzswVEwAlgwIDAQAB";
    public static final String RSA_PUBLICE =
            "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDNQDs3peFeKvvl/lcOzatuEYiC\n" +
                    "V5bUF/xD/ldrBFswOQaDszxY5Up/sl4HGNRqMAomgAlOoNM1cXulmdFX7M6mzv2S\n" +
                    "48hT8GNJwPsG/dvaourQ6//EL/AC/Ue/t8nWCHToKct2ejbDShXKHLsqtsoh5Gb+\n" +
                    "PWjwdh1a1od+h3ZlZwIDAQAB\n";
    public static final String RSA_PRIVATE =
            "MIICXQIBAAKBgQDNQDs3peFeKvvl/lcOzatuEYiCV5bUF/xD/ldrBFswOQaDszxY\n" +
                    "5Up/sl4HGNRqMAomgAlOoNM1cXulmdFX7M6mzv2S48hT8GNJwPsG/dvaourQ6//E\n" +
                    "L/AC/Ue/t8nWCHToKct2ejbDShXKHLsqtsoh5Gb+PWjwdh1a1od+h3ZlZwIDAQAB\n" +
                    "AoGADZRiVpwy/Pf7EoxxVhllbjLaxUTmRcIQfq8lOX9gSSB8vdnt9DO3ahty/SU3\n" +
                    "aI8lHMb71qftUWvgsmQq5ZZVVbWlpT7eAFT1cauizPfMZeIrhwqLIPIvixR3w0+o\n" +
                    "hBRE+MLfHnEFtrpJXVYTU5qZ/Ca3DQU8h2JiYWvOhGOrqIECQQDp1juG1CPCBilx\n" +
                    "cRh2CzwsYKspCTtuNrOUdocW0dZzug3yWBC3yCbBWMpAWcBY+2h+8+PMB6aPM1/e\n" +
                    "s7KodH4dAkEA4LRlRDOG6gIMaMfFSOpC6qXxcooqc0oAxEfJqqlfLixiukqzNmDt\n" +
                    "xiKSUIiE8F7bXMI7uY3i/9fOrTQjmCfqUwJBAL6+DTKPS1fSlO2/dlecFIqSlCvW\n" +
                    "Jw9hOZ1qDgnUQ12FMCk2IvT3JH3lAp35WEh9U6DzKydcOkZnftV3uc1lsRUCQEWe\n" +
                    "frWXxVghVFjudCh4NE1hJqKXPjnEFuK5XzkaCtxScjBHzqitdV3q/iwncBDNQufF\n" +
                    "Yh3GYStlYKp3OgP9cfMCQQCAG9IXppb2aFPQQQiOWf8BSimzaVTORphQL83VBsKp\n" +
                    "B74ZVjhs0cXBS1DBPZ7LTO8goFzF1R4Nz+d6Q18f3vCQ\n";
    private static final String ALGORITHM = "RSA";

    /**
     * 得到公钥
     *
     * @param algorithm
     * @param bysKey
     * @return
     */
    private static PublicKey getPublicKeyFromX509(String algorithm,
                                                  String bysKey) throws NoSuchAlgorithmException, Exception {
        byte[] decodedKey = Base64.decode(bysKey, Base64.DEFAULT);
        X509EncodedKeySpec x509 = new X509EncodedKeySpec(decodedKey);

        KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
        return keyFactory.generatePublic(x509);
    }

    /**
     * 使用公钥加密
     *
     * @param content
     * @param key
     * @return
     */
    public static String encryptByPublic(String content) {
        try {
           // PublicKey pubkey = getPublicKeyFromX509(ALGORITHM, RSA_PUBLICE);
            PublicKey pubkey = getPublicKeyFromX509(ALGORITHM, RSA_PUBLICE);
            // Log.e("sub", "公钥:" + RSA_PUBLICE);
            // RSACipherStrategy.printPublicKeyInfo(pubkey);
            // Cipher cipher = Cipher.getInstance(RSAUtils.CIPHER);
            Cipher cipher = Cipher.getInstance(RSAUtils.CIPHER);
            //Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, pubkey);

            byte plaintext[] = content.getBytes("UTF-8");
            byte[] output = cipher.doFinal(plaintext);

            String s = new String(Base64.encode(output, Base64.DEFAULT));

            return s;
            // 必须先encode成 byte[]，再转成encodeToString，否则服务器解密会失败
//            byte[] encode = Base64.encode(output, Base64.DEFAULT);
//            return Base64.encodeToString(encode, Base64.DEFAULT);
        } catch (Exception e) {
            Log.e("sub", e.getMessage() + "|加密");
            return null;
        }
    }

    /**
     * 使用公钥解密
     * 使用私钥解密<br/>
     *
     * @param content 密文
     * @param key     商户私钥
     * @return 解密后的字符串
     */
    public static String decryptByPublic(String content) {
        try {
            PublicKey pubkey = getPublicKeyFromX509(ALGORITHM, RSA_PUBLICE);
            // Log.e("sub", "私钥:" + RSA_PRIVATE);
            // 解密
            PrivateKey privateKey = RSAUtils.loadPrivateKey(RSA_PRIVATE);
            //RSACipherStrategy.printPrivateKeyInfo(privateKey);
            Cipher cipher = Cipher.getInstance(RSAUtils.CIPHER);
            //Cipher cipher = Cipher.getInstance(ALGORITHM);
           cipher.init(Cipher.DECRYPT_MODE, privateKey);
            //cipher.init(Cipher.DECRYPT_MODE, pubkey);
            //byte[] output = cipher.doFinal(Base64.decode(content, Base64.DEFAULT));
            boolean tst = true;
            if (tst) {
               // return new String(output);
            }
            InputStream ins = new ByteArrayInputStream(Base64.decode(content,
                    Base64.DEFAULT));
            ByteArrayOutputStream writer = new ByteArrayOutputStream();
            //byte[] buf = new byte[128];
            byte[] buf = new byte[128];
            int bufl;
            while ((bufl = ins.read(buf)) != -1) {
                byte[] block = null;
                if (buf.length == bufl) {
                    block = buf;
                } else {
                    block = new byte[bufl];
                    for (int i = 0; i < bufl; i++) {
                        block[i] = buf[i];
                    }
                }
                writer.write(cipher.doFinal(block));
            }
            // byte[] bytes = Base64.decode(writer.toByteArray(),Base64.DEFAULT);
            Log.e("sub", "#解密后#"+new String(writer.toByteArray()));
            return new String(writer.toByteArray(), "utf-8");
            //return new String(bytes, "utf-8");
        } catch (Exception e) {
            Log.e("sub", e + "|解密异常||||||");
            return null;
        }
    }

    public static String getMD5(String content) {
        String s = null;
        char hexDigits[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
                'a', 'b', 'c', 'd', 'e', 'f'};
        try {
            java.security.MessageDigest md = java.security.MessageDigest
                    .getInstance("MD5");
            md.update(content.getBytes());
            byte tmp[] = md.digest();
            char str[] = new char[16 * 2];
            int k = 0;
            for (int i = 0; i < 16; i++) {
                byte byte0 = tmp[i];
                str[k++] = hexDigits[byte0 >>> 4 & 0xf];
                str[k++] = hexDigits[byte0 & 0xf];
            }
            s = new String(str);

        } catch (Exception e) {
            e.printStackTrace();
        }
        return s;
    }

}
