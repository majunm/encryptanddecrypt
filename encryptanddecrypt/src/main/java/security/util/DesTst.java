package security.util;

import java.io.UnsupportedEncodingException;
import java.security.Key;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * 作者：马俊
 * 时间：2018/4/13 下午1:49
 * 邮箱：747673016@qq.com
 */

public class DesTst {
    //    private final static String DES = "DES";
    private final static String DES = "DESede";
    public static String KEY = "channel3des_012345678910"; //24位

    private static final String S_KEY_ALGORITHM = "DESede";
    private static final String S_CIPHER_ALGORITHM = "DESede/ECB/PKCS5Padding";

    /** 算法/模式/填充 **/
    private static final String PADDING_MODE = "desede/ECB/PKCS5Padding";
    private static SecretKey skSecretkey;
    /** 创建密钥 **/
    private static SecretKeySpec createKey(String key) {
        byte[] data = null;
        if (key == null) {
            key = "";
        }
        StringBuffer sb = new StringBuffer(16);
        sb.append(key);
        while (sb.length() < 16) {
            sb.append("0");
        }
        if (sb.length() > 16) {
            sb.setLength(16);
        }

        try {
            data = sb.toString().getBytes("UTF-8");
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        return new SecretKeySpec(data, "AES");
    }
    public static byte[] enc(byte[] byteaPlainText, SecretKey skSecretkey) throws Exception {
        Cipher cipher = Cipher.getInstance(S_CIPHER_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, skSecretkey);
        byte[] byteaCryptograph = cipher.doFinal(byteaPlainText);
        return byteaCryptograph;
    }

    public static byte[] dec(byte[] byteaCryptograph, SecretKey skSecretkey) throws Exception {
        Cipher cCipher = Cipher.getInstance(S_CIPHER_ALGORITHM);
        cCipher.init(Cipher.DECRYPT_MODE, skSecretkey);
        byte[] byteaPlainText = cCipher.doFinal(byteaCryptograph);
        return byteaPlainText;
    }

    public static Key generateKey(int iBits) throws Exception {
        // iBits = 112;
        KeyGenerator kg = KeyGenerator.getInstance(S_KEY_ALGORITHM);
        kg.init(iBits);
        skSecretkey = kg.generateKey();
        return skSecretkey;
    }

    public static void main1(String[] args) throws Exception {
        String sHexPlainText = "0123456789abcdef";
//        SecretKey skSecretkey = (SecretKey) generateKey(112);
        SecretKey skSecretkey = (SecretKey) generateKey(112);
        byte[] byteaPlainText = hexStr2ByteArr(sHexPlainText);
        byte[] byteaCryptograph = enc(byteaPlainText, skSecretkey);
        byte[] byteaPlainTextAftDec = dec(byteaCryptograph, skSecretkey);
        System.out.println("原明文byte[]长度:" + byteaPlainText.length + "\t相应的16进制字符串值:" + byteArr2HexStr(byteaPlainText));
        System.out.println("加密后byte[]长度:" + byteaCryptograph.length + "\t相应的16进制字符串值:" + byteArr2HexStr(byteaCryptograph));
        //3Py0RXsMSrUg0vW57R/Rq5D6vLJzu7ofL/T409UPiGirhw0CI0vGbcpYy5ukBWFL
        String x = "3Py0RXsMSrUg0vW57R/Rq5D6vLJzu7ofL/T409UPiGirhw0CI0vGbcpYy5ukBWFL";
        String y = x;
//         y = new String(Base64Utils.decode(x));
//        y = new String(Base64.decode(x,Base64.DEFAULT));
//        y = new String(java.util.Base64.getMimeDecoder().decode(x));
        System.out.println("Base64Utils解密=" + y);
        System.out.println("解密后byte[]长度:" + byteaPlainTextAftDec.length + "\t相应的16进制字符串值:" + byteArr2HexStr(byteaPlainTextAftDec));
        y = new String(dec(y.getBytes(), skSecretkey));
        System.out.println("解密后=" + y);
    }

    public static String byteArr2HexStr(byte[] bytea) throws Exception {
        String sHex = "";
        int iUnsigned = 0;
        StringBuffer sbHex = new StringBuffer();
        for (int i = 0; i < bytea.length; i++) {
            iUnsigned = bytea[i];
            if (iUnsigned < 0) {
                iUnsigned += 256;
            }
            if (iUnsigned < 16) {
                sbHex.append("0");
            }
            sbHex.append(Integer.toString(iUnsigned, 16));
        }
        sHex = sbHex.toString();
        return sHex;
    }


    public static byte[] hexStr2ByteArr(String sHex) throws Exception {

        if (sHex.length() % 2 != 0) {
            sHex = "0" + sHex;
        }
        byte[] bytea = bytea = new byte[sHex.length() / 2];

        String sHexSingle = "";
        for (int i = 0; i < bytea.length; i++) {
            sHexSingle = sHex.substring(i * 2, i * 2 + 2);
            bytea[i] = (byte) Integer.parseInt(sHexSingle, 16);
        }
        return bytea;
    }


    // 密钥
    private final static String secretKey = KEY;
    // 向量
    private final static String iv = "huijin66";
    // 加解密统一使用的编码方式
    private final static String encoding = "utf-8";

    /**
     * 3DES加密
     *
     * @param plainText 普通文本
     * @return
     * @throws Exception
     */
    public static String encode(String plainText) {
        Key deskey = null;
        try {
            DESedeKeySpec spec = new DESedeKeySpec(secretKey.getBytes());
            SecretKeyFactory keyfactory = SecretKeyFactory.getInstance("desede");
            deskey = keyfactory.generateSecret(spec);

//            Cipher cipher = Cipher.getInstance("desede/CBC/PKCS5Padding");
//            Cipher cipher = Cipher.getInstance("desede/ECB/PKCS5Padding");
            Cipher cipher = Cipher.getInstance(PADDING_MODE);
//            IvParameterSpec ips = new IvParameterSpec(iv.getBytes());
//            cipher.init(Cipher.ENCRYPT_MODE, deskey, ips);
            cipher.init(Cipher.ENCRYPT_MODE, deskey);
            byte[] encryptData = cipher.doFinal(plainText.getBytes(encoding));
            return Base64Utils.encode(encryptData);
        } catch (Exception e) {
            e.printStackTrace();
            return plainText;
        }
    }

    /**
     * 3DES解密
     *
     * @param encryptText 加密文本
     * @return
     * @throws Exception
     */
    public static String decode(String encryptText) {
        Key deskey = null;
        try {
            DESedeKeySpec spec = new DESedeKeySpec(secretKey.getBytes());
            SecretKeyFactory keyfactory = SecretKeyFactory.getInstance("desede");
            deskey = keyfactory.generateSecret(spec);
//            Cipher cipher = Cipher.getInstance("desede/CBC/PKCS5Padding");
//            Cipher cipher = Cipher.getInstance("desede/ECB/PKCS5Padding");
            Cipher cipher = Cipher.getInstance(PADDING_MODE);
            //IvParameterSpec ips = new IvParameterSpec(iv.getBytes());
//            cipher.init(Cipher.DECRYPT_MODE, deskey, ips); // 不要偏移向量
            cipher.init(Cipher.DECRYPT_MODE, deskey);
//            encryptText = new String(String2byte(encryptText.getBytes()));
            byte[] decryptData = cipher.doFinal(Base64Utils.decode(encryptText));
            //return new String(String2byte(decryptData), encoding);
            return new String(decryptData, encoding);
        } catch (Exception e) {
            e.printStackTrace();
            return encryptText;
        }
    }

    /**
     * 填充
     *
     * @param b
     * @return
     */
    public static byte[] String2byte(byte[] b) {
        if ((b.length % 2) != 0)
            throw new IllegalArgumentException("长度不是偶数");
        byte[] b2 = new byte[b.length / 2];
        for (int n = 0; n < b.length; n += 2) {
            String item = new String(b, n, 2);
            b2[n / 2] = (byte) Integer.parseInt(item, 16);
        }
        return b2;
    }

    public static void main(String[] args) {
        try {
            String password = "{\"sign\":\"xxxxxxxxxxxxxxxxxxxx\",\"amount\":\"1000\",\"payer\":\"11111111111\",\"attach\":\"备注\",\"buyer\":\"93237040\",\"clientIp\":\"0.0.0.0\",\"productName\":\"产品名称\",\"productId\":\"123456\",\"appKey\":\"012345678910\"}";//密码
            System.out.println("加密前的字符串:" + password);
            String y = password;
            System.out.println("加密:" + encode(y));
            String x = "3Py0RXsMSrUg0vW57R/Rq5D6vLJzu7ofL/T409UPiGirhw0CI0vGbcpYy5ukBWFL";
            System.out.println("解密:" + decode(x));
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println(e);
        }
    }
}
