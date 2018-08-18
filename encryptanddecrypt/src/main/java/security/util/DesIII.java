package security.util;

import java.io.IOException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;

/**
 * 作者：马俊
 * 时间：2018/4/13 下午1:49
 * 邮箱：747673016@qq.com
 */

public class DesIII {
    /**
     * 根据参数生成Key;
     *
     * @param strKey
     */
    private Key getKey(String strKey) {
        Key key = null;
        try {
            KeyGenerator _generator = KeyGenerator.getInstance("DES");
            _generator.init(new SecureRandom(strKey.getBytes()));
            key = _generator.generateKey();
            _generator = null;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return key;
    }

    /**
     * 获得一次3DES加密后的密文
     *
     * @param
     * @return strMi
     */
    public String getEncString(String strMing, String strKey) {
        byte[] byteMi = null;
        byte[] byteMing = null;
        String strMi = "";
        Key key = getKey(strKey);
//        BASE64Encoder encoder = new BASE64Encoder();
        try {
            byteMing = strMing.getBytes("utf-8");
            byteMi = getEncCode(byteMing, key);
            strMi = Base64Utils.encode(byteMi);
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            byteMi = null;
            byteMing = null;
        }
        return strMi;
    }

    /**
     * 获得两次3DES加密后的密文
     *
     * @param
     * @return strMi
     */
    public String getTwiceEncString(String strMing, String strKey) {
        return getEncString(getEncString(strMing, strKey), strKey);
    }

    /**
     * 获得一次3DES解密后的明文
     *
     * @param
     * @return strMing
     */
    public String getDecString(String strMi, String strKey) {
//        BASE64Decoder base64Decoder = new BASE64Decoder();
        byte[] byteMing = null;
        byte[] byteMi = null;
        String strMing = "";
        Key key = getKey(strKey);
        try {
            byteMi = Base64Utils.decode(strMi);
            byteMing = getDecCode(byteMi, key);
            strMing = new String(byteMing, "utf-8");
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            byteMing = null;
            byteMi = null;
        }
        return strMing;
    }

    /**
     * 获得两次3DES解密后的明文
     *
     * @param
     * @return strMing
     */
    public String getTwiceDecString(String strMi, String strKey) {
        return getDecString(getDecString(strMi, strKey), strKey);
    }

    /**
     * 获得一次3DES加密后的密文
     *
     * @param byts
     * @return
     */
    private byte[] getEncCode(byte[] byts, Key key) {
        byte[] byteFina = null;
        Cipher cipher;
        try {
            cipher = Cipher.getInstance("DES");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            byteFina = cipher.doFinal(byts);
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            cipher = null;
        }
        return byteFina;
    }

    /**
     * 获得一次3DES解密后的明文
     *
     * @param bytd
     * @return
     */
    private byte[] getDecCode(byte[] bytd, Key key) {
        byte[] byteFina = null;
        Cipher cipher = null;
        try {
            cipher = Cipher.getInstance("DES");
            cipher.init(Cipher.DECRYPT_MODE, key);
            byteFina = cipher.doFinal(bytd);
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            cipher = null;
        }
        return byteFina;
    }
    public static String KEY = "4oTwjd95NpGLVDl8AxDKAMmUB2mUjG8q";
    public static void main(String[] args) {
        DesIII td = new DesIII();
        Key k = td.getKey(KEY);
        System.out.println("获得的密钥key是:" + k);
        String encyStr = td.getEncString("Test", "Key");
        System.out.println("一次加密后的密文是:" + encyStr);
        String decyStr = td.getDecString(encyStr, "Key");
        System.out.println("一次解密后的明文是:" + decyStr);
        encyStr = td.getTwiceEncString("Test", "Key");
        System.out.println("两次加密后的密文是:" + encyStr);
        decyStr = td.getTwiceDecString(encyStr, "Key");
        System.out.println("两次解密后的明文是:" + decyStr);
    }
}
