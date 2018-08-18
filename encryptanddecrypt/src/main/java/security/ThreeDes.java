package security;

import org.apache.commons.codec.binary.Base64;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.SecretKeySpec;

import security.util.Base64Utils;
import security.util.DesTst;

//import org.apache.commons.codec.binary.Base64;


/*字符串 DESede(3DES) 加密
 * ECB模式/使用PKCS7方式填充不足位,目前给的密钥是192位
 * 3DES（即Triple DES）是DES向AES过渡的加密算法（1999年，NIST将3-DES指定为过渡的
 * 加密标准），是DES的一个更安全的变形。它以DES为基本模块，通过组合分组方法设计出分组加
 * 密算法，其具体实现如下：设Ek()和Dk()代表DES算法的加密和解密过程，K代表DES算法使用的
 * 密钥，P代表明文，C代表密表，这样，
 * 3DES加密过程为：C=Ek3(Dk2(Ek1(P)))
 * 3DES解密过程为：P=Dk1((EK2(Dk3(C)))
 * */
public class ThreeDes {

    /**
     * @param args在java中调用sun公司提供的3DES加密解密算法时，需要使
     * 用到$JAVA_HOME/jre/lib/目录下如下的4个jar包：
     * jce.jar
     * security/US_export_policy.jar
     * security/local_policy.jar
     * ext/sunjce_provider.jar
     */

    private static final String Algorithm = "DESede"; //定义加密算法,可用 DES,DESede,Blowfish

    public static String enc(String src) {
//        String pword = Base64.encodeBase64String(encryptMode(
//                key_key.getBytes(), src.getBytes()));
//        return pword;
        return new String(Base64Utils.encode(encryptMode(
                key_key.getBytes(), src.getBytes())));
//        return android.util.Base64.encodeToString(,android.util.Base64.DEFAULT);
    }

    public static String dec(String src) {
        String x = new String(decryptMode(key_key.getBytes(), src.getBytes()));
        byte[] xx = Base64Utils.decode(x);
        return new String(xx);
    }

    //keybyte为加密密钥，长度为24字节
    //src为被加密的数据缓冲区（源）
    public static byte[] encryptMode(byte[] keybyte, byte[] src) {
        Key deskey = null;

        try {
            DESedeKeySpec spec = new DESedeKeySpec(keybyte);
            SecretKeyFactory keyfactory = SecretKeyFactory.getInstance(Algorithm);
            deskey = keyfactory.generateSecret(spec);
            Cipher cipher = Cipher.getInstance(Algorithm + "/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, deskey);
            byte[] bOut = cipher.doFinal(src);
            return bOut;
//            android.util.Base64.encodeToString(bOut,android.util.Base64.DEFAULT)
//            return android.util.Base64.encode(bOut,);
        } catch (InvalidKeyException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (BadPaddingException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return null;

    }

    //keybyte为加密密钥，长度为24字节
    //src为加密后的缓冲区
    public static byte[] decryptMode(byte[] keybyte, byte[] src) {
        try {
            //生成密钥
            SecretKey deskey = new SecretKeySpec(keybyte, Algorithm);
            //解密
            Cipher c1 = Cipher.getInstance(Algorithm);
            c1.init(Cipher.DECRYPT_MODE, deskey);
            return c1.doFinal(src);
        } catch (NoSuchAlgorithmException e1) {
            e1.printStackTrace();
        } catch (NoSuchPaddingException e2) {
            e2.printStackTrace();
        } catch (Exception e3) {
            e3.printStackTrace();
        }
        return null;
    }

    //转换成十六进制字符串
    public static String byte2Hex(byte[] b) {
        String hs = "";
        String stmp = "";
        for (int n = 0; n < b.length; n++) {
            stmp = (Integer.toHexString(b[n] & 0XFF));
            if (stmp.length() == 1) {
                hs = hs + "0" + stmp;
            } else {
                hs = hs + stmp;
            }
            if (n < b.length - 1) hs = hs + ":";
        }
        return hs.toUpperCase();
    }

    public static final String key_key = "channel3des_012345678910"; //秘钥

    public static void main(String[] args) throws UnsupportedEncodingException {
        //添加新安全算法,如果用JCE就要把它添加进去
        byte[] key = key_key.getBytes();

//        //Security.addProvider(new com.sun.crypto.provider.SunJCE());
//        String password = "{\"sign\":\"xxxxxxxxxxxxxxxxxxxx\",\"amount\":\"1000\",\"payer\":\"11111111111\",\"attach\":\"备注\",\"buyer\":\"93237040\",\"clientIp\":\"0.0.0.0\",\"productName\":\"产品名称\",\"productId\":\"123456\",\"appKey\":\"012345678910\"}";//密码
//        System.out.println("加密前的字符串:" + password);
////        byte[] encoded = encryptMode(key, password.getBytes());
////
////        String pword = enc(password);
////        String pword = Base64.encodeBase64String(encoded);
////        System.out.println("加密后的字符串:" + pword+"@||||||||");
//        //System.out.println(new String(Base64.decodeBase64("/FvK745V9uUAPIKAa7Db7zsJwEjL4EGHgLZvNMRmnbJ1K8iVs4H1ika4wkfGmQy7ibMmdgnfy0OOB65t05OkXtrvLE3ZM75WUnCWwjxh0PZE70nK8NkxtXiCIH3xqgBO8hwbVrzjoMOv2Nsk5QO37Vo/azN3t7xc2volr3i2FlabMLD7yV4oFW85QoCuylO6H+b3YyttytqxUOaLw7L0pVmJMuYcu/WxEa3I6hMbFHDYxGFtkDwmf+g==")));
//        byte[] srcBytes = decryptMode(key, Base64Utils.decode("3Rg8+8GXjMLLyFbYaFarPp/ntzraxC0a1Wsa5okZVpTWhJIy87dgwTsM5hHzjrCHWhAduzB8DQVdk7u3Fa2f8uQ/R4Hte8+B/UEvCB0oYpMoAm82pPI0s4e6M7RBViG0xWOjqeZhUBuK9LL2+wVFRjsM5hHzjrCHWhAduzB8DQWSluxBX2Qpuk3KQ57NkkHYDMcwaCzMIhp614L0455z/em3SbTefgM2CmW4mqWxfkiBtg0bkx1lYOHuMCXMpPLx8XtjL3lyFq4SKR/P14yCHvpR4AK+0VGRI5A4kZJy90kQfxm5puKQh0JbYxzxj3zXYHSj1nQlqjEx98JpPrXjZe7a83mqg25o8MCAOWiBvJG6YZPP0WmCXgi/da2LzR+jGLjCAwe61XBZ3YYRBmbSBeJcflK18tS7tgHclECMDd9giKrSK4Z3c6U5vKlPczDY"));
//        String x = "3Py0RXsMSrUg0vW57R/Rq5D6vLJzu7ofL/T409UPiGirhw0CI0vGbcpYy5ukBWFL";
//
//        System.out.println("解密:" + dec(x));
//        System.out.println("解密后的字符串:" + new String(srcBytes, "UTF-8"));
//        byte[] srcBytes2 = decryptMode(key, Base64Utils.decode(x));
//        System.out.println("解密后的字符串2:" + new String(srcBytes2, "UTF-8"));
//
//
        String xx = "123";
        System.out.println("加密前:" + xx);
        byte[] encoded = encryptMode(key, xx.getBytes());
        String pword = Base64.encodeBase64String(encoded);
        System.out.println("加密后:" + pword);
        byte[] xxxx = decryptMode(key, Base64Utils.decode(pword));
        System.out.println("解密后:" + new String(xxxx));

        System.out.println("android加密前:" + xx);
        String qq = DesTst.encode(xx);
        // Given final block not properly padded
        System.out.println("android加密后:" + qq);
        String dd = DesTst.decode(qq);
        System.out.println("android解密后:" + dd);
        //ygfPZeAJk/ns3/goum91y8d5ybgJizat7nxozg/d7Z62oREMYBXQ4sL1gLbJ8TiWtI4j3SdwrLA=
        String kk = "ygfPZeAJk/ns3/goum91y8d5ybgJizat7nxozg/d7Z62oREMYBXQ4sL1gLbJ8TiWtI4j3SdwrLA=";

        String ddd = DesTst.decode(kk);
        System.out.println("android解密后:" + ddd);
    }
}

