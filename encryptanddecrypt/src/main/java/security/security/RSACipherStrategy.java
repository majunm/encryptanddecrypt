package security.security;

import android.util.Log;


import java.io.InputStream;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import security.config.Rsa;
import security.security.util.RSAUtils;

public class RSACipherStrategy extends CipherStrategy {

    private PublicKey mPublicKey;
    private PrivateKey mPrivateKey;

    public void initPublicKey(String publicKeyContentStr) {
        try {
            publicKeyContentStr = Rsa.RSA_PUBLICE;
            mPublicKey = RSAUtils.loadPublicKey(publicKeyContentStr);
            printPublicKeyInfo(mPublicKey);
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("" + e.getMessage());
        }
    }

    public void initPublicKey(InputStream publicKeyIs) {
        try {
            mPublicKey = RSAUtils.loadPublicKey(publicKeyIs);
            printPublicKeyInfo(mPublicKey);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void initPrivateKey(String privateKeyContentStr) {
        try {
            privateKeyContentStr = "MIICXQIBAAKBgQDNQDs3peFeKvvl/lcOzatuEYiCV5bUF/xD/ldrBFswOQaDszxY\n" +
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
            mPrivateKey = RSAUtils.loadPrivateKey(privateKeyContentStr);
            printPrivateKeyInfo(mPrivateKey);
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("" + e.getMessage());
        }
    }

    public void initPrivateKey(InputStream privateIs) {
        try {
            mPrivateKey = RSAUtils.loadPrivateKey(privateIs);
            printPrivateKeyInfo(mPrivateKey);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Override
    public String encrypt(String content) {
        if (mPublicKey == null) {
            throw new NullPointerException(
                    "PublicKey is null, please init it first");
        }
        byte[] encryptByte = RSAUtils.encryptData(content.getBytes(),
                mPublicKey);

        return encodeConvert(encryptByte);
    }

    @Override
    public String decrypt(String encryptContent) {
        if (mPrivateKey == null) {
            throw new NullPointerException(
                    "PrivateKey is null, please init it first");
        }
        byte[] encryptByte = decodeConvert(encryptContent);
        byte[] decryptByte = RSAUtils.decryptData(encryptByte, mPrivateKey);

        return new String(decryptByte);
    }

    /**
     * 打印公钥信息
     *
     * @param publicKey
     */
    public static void printPublicKeyInfo(PublicKey publicKey) {
        RSAPublicKey rsaPublicKey = (RSAPublicKey) publicKey;
        Log.e("sub","----------RSAPublicKey----------");
        Log.e("sub","Modulus.length=" + rsaPublicKey.getModulus().bitLength());
        Log.e("sub","Modulus=" + rsaPublicKey.getModulus().toString());
        Log.e("sub","PublicExponent.length=" + rsaPublicKey.getPublicExponent().bitLength());
        Log.e("sub","PublicExponent=" + rsaPublicKey.getPublicExponent().toString());
    }

    public static void printPrivateKeyInfo(PrivateKey privateKey) {
        RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) privateKey;
        Log.e("sub","----------RSAPrivateKey ----------");
        Log.e("sub","Modulus.length=" + rsaPrivateKey.getModulus().bitLength());
        Log.e("sub","Modulus=" + rsaPrivateKey.getModulus().toString());
        Log.e("sub","PrivateExponent.length=" + rsaPrivateKey.getPrivateExponent().bitLength());
        Log.e("sub","PrivatecExponent=" + rsaPrivateKey.getPrivateExponent().toString());
    }
}
