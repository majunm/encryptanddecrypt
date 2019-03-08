```
Key.KEY = "密钥"; // 和服务器的约定,剩下的调用即可
System.out.println("AES加密后="+AesEncryptionUtil.encrypt("123456")+
                "\nAES解密后="+AesEncryptionUtil.decrypt(AesEncryptionUtil.encrypt("123456"))+
                "RSA加密后="+ Rsa.encryptByPublic("123456")+
                "\nRSA解密后="+Rsa.decryptByPublic(Rsa.encryptByPublic("123456"))
        );
```

php升级
```
package security.util;


import java.io.UnsupportedEncodingException;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import security.security.Key;

/**
 算法/模式/填充                        16字节加密后数据长度         不满16字节加密后长度
 AES/CBC/NoPadding                               16                                       不支持
 AES/CBC/PKCS5Padding                        32                                          16
 AES/CBC/ISO10126Padding                  32                                           16
 AES/CFB/NoPadding                               16                                  原始数据长度
 AES/CFB/PKCS5Padding                        32                                           16
 AES/CFB/ISO10126Padding                  32                                            16
 AES/ECB/NoPadding                               16                                         不支持
 AES/ECB/PKCS5Padding                        32                                            16
 AES/ECB/ISO10126Padding                   32                                           16
 AES/OFB/NoPadding                               16                                   原始数据长度
 AES/OFB/PKCS5Padding                        32                                            16
 AES/OFB/ISO10126Padding                  32                                             16
 AES/PCBC/NoPadding                             16                                        不支持
 AES/PCBC/PKCS5Padding                      32                                             16
 AES/PCBC/ISO10126Padding                32                                             16
 AES-256-CBC
 */
public class AesEncryptionUtil {
	/** 算法/模式/填充 **/
//	private static final String CipherMode = "AES/CBC/NoPadding";
	private static final String CipherMode = "AES/CBC/PKCS5Padding";
//	private static final String CipherMode = "AES/CBC/ISO10126Padding";

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

	private static IvParameterSpec createIV(String password) {
		byte[] data = null;
		if (password == null) {
			password = "";
		}
		StringBuffer sb = new StringBuffer(16);
		sb.append(password);
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
		return new IvParameterSpec(data);
	}

	/** 加密字节数据 **/
	public static byte[] encrypt(byte[] content, String password, String iv) {
		try {
			// String encryptResultStr = parseByte2HexStr(content);
			SecretKeySpec key = createKey(password);
			Cipher cipher = Cipher.getInstance(CipherMode);
			cipher.init(Cipher.ENCRYPT_MODE, key, createIV(iv));
			int len = content.length;
			/* 计算补0后的长度 */
			//padding 去掉这个
//			while (len % 16 != 0) {
//				len++;
//			}
			byte[] sraw = new byte[len];
			/* 在最后补0 */
			for (int i = 0; i < len; ++i) {
				if (i < content.length) {
					sraw[i] = content[i];
				} else {
					sraw[i] = 0;
				}
			}
			return cipher.doFinal(sraw);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

	/**
	 * 将二进制转换成16进制
	 * 
	 * @param buf
	 * @return
	 */
	public static String parseByte2HexStr(byte buf[]) {
		StringBuffer sb = new StringBuffer();
		for (int i = 0; i < buf.length; i++) {
			String hex = Integer.toHexString(buf[i] & 0xFF);
			if (hex.length() == 1) {
				hex = '0' + hex;
			}
			sb.append(hex.toUpperCase());
		}
		return sb.toString();
	}

	/**
	 * 将16进制转换为二进制
	 * 
	 * @param hexStr
	 * @return
	 */
	public static byte[] parseHexStr2Byte(String hexStr) {
		if (hexStr.length() < 1) {
			return null;
		}
		byte[] result = new byte[hexStr.length() / 2];
		for (int i = 0; i < hexStr.length() / 2; i++) {
			int high = Integer.parseInt(hexStr.substring(i * 2, i * 2 + 1), 16);
			int low = Integer.parseInt(hexStr.substring(i * 2 + 1, i * 2 + 2),
					16);
			result[i] = (byte) (high * 16 + low);
		}
		return result;
	}

	/**
	 * 加密
	 */
	public static String encrypt(String content) {
		return encrypt(content, Key.KEY, Key.KEYIV);
	}

	/** 加密(结果为16进制字符串) **/
	public static String encrypt(String content, String password, String iv) {
		byte[] data = null;
		try {
			data = content.getBytes("UTF-8");
		} catch (Exception e) {
			e.printStackTrace();
		}
		data = encrypt(data, password, iv);
		return Base64Utils.encode(data);
	}

	/** 解密字节数组 **/
	public static byte[] decrypt(byte[] content) {
		return decrypt(content, Key.KEY, Key.KEYIV);
	}

	/** 解密字节数组 **/
	public static byte[] decrypt(byte[] content, String password, String iv) {
		try {
			SecretKeySpec key = createKey(password);
			Cipher cipher = Cipher.getInstance(CipherMode);
			cipher.init(Cipher.DECRYPT_MODE, key, createIV(iv));
			byte[] result = cipher.doFinal(content);
			return result;
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

	/** 解密(输出结果为字符串) **/
	public static String decrypt(String content) {
		return decrypt(content, Key.KEY, Key.KEYIV);
	}

	/** 解密(输出结果为字符串) **/
	public static String decrypt(String content, String password, String iv) {
		byte[] data = null;
		try {
			data = Base64Utils.decode(content);
		} catch (Exception e) {
			e.printStackTrace();
		}
		data = decrypt(data, password, iv);
		if (data == null) {
			return null;
		}
		String result = null;
		try {
			result = new String(data, "UTF-8").trim();
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}
		return result;
	}

	/** 字节数组转成16进制字符串 **/
	public static String byte2hex(byte[] b) { // 一个字节的数，
		StringBuffer sb = new StringBuffer(b.length * 2);
		String tmp = "";
		for (int n = 0; n < b.length; n++) {
			// 整数转成十六进制表示
			tmp = (Integer.toHexString(b[n] & 0XFF));
			if (tmp.length() == 1) {
				sb.append("0");
			}
			sb.append(tmp);
		}
		// return sb.toString().toUpperCase(); // 转成大写
		return sb.toString(); // 转成大写
	}

	/** 将hex字符串转换成字节数组 **/
	public static byte[] hex2byte(String inputString) {
		if (inputString == null || inputString.length() < 2) {
			return new byte[0];
		}
		inputString = inputString.toLowerCase();
		int l = inputString.length() / 2;
		byte[] result = new byte[l];
		for (int i = 0; i < l; ++i) {
			String tmp = inputString.substring(2 * i, 2 * i + 2);
			result[i] = (byte) (Integer.parseInt(tmp, 16) & 0xFF);
		}
		return result;
	}
}

```

```

/**
 'key' => '8302255168a9931cd634ecaf94b7b196',
 'iv' => '68882fbfe20024d3',
 */
public class Key {
    /**
     * 密钥
     */
//    public static final String KEY = "$75k!xxH&$EhQLmv"; // 密钥
    public static final String KEY = "8302255168a9931cd634ecaf94b7b196"; // 密钥
    /**
     * 密钥偏移
     */
//    public static final String KEYIV = MD5Utils.md5(KEY).substring(0, 16); // 密钥偏移
    public static final String KEYIV = "68882fbfe20024d3"; // 密钥偏移

    public static void main(String[] args) {
       // String encrypti = AesEncryptionUtil.encrypt("{\"device_id\":\"106\",\"imei\":\"867080022320760\"}");
       // System.out.println("加密:"+encrypti);
//        System.out.println("解密:"+AesEncryptionUtil.decrypt(encrypti));
//        System.out.println("解密:"+AesEncryptionUtil.decrypt("Egyx6AizeLBKTbp34hwOmg=="));
//        String x = new String(Base64Utils.decode("gEnP9PSQhNJ8MPUSeI9fcBnzEsBdxpYX8ozRfV2mKKvUSHYx2DvY3IMG/jteYp38"));
//        System.out.println(x);
        String x = "";
//        String decrypt = AesEncryptionUtil.decrypt(x="\"/KuDpmsU3ECb++fDCKuf4OeXBvPXzS+//+/MKf4O7tWXzliMhLkEV7wVUfyq0iDTwP+7vn6/60Z31rk6+6yNHlW8aCgi2ecG4R1pv9gvrurbKdAlBs78EgQf5Q056MI9TSn2PHi9QCXtZ4uJYsS8pB3QEMIZxdEc4nGoz8fySuk51dlWFApzF0fFszDvRwycjEZpciK1fW3gMeXVys37jzvfcrqixOnKv7HpOmw3\"");
//        String decrypt = AesEncryptionUtil.decrypt(x="\"4cOJTE9cC7cghKkPG1k7KFbRpAaZ769JCT2GlsAWL8p96f1zuIX1EXh4x3b83a8RB6vPn5I7yq0glV24sD82rgO5sdIqKqKLwUGQYOGPfvYffjy8YWrFtwMSBQ88z8gs\"");
//        String decrypt = AesEncryptionUtil.decrypt(x="\"/h7F1U2vBMa64zSZDgXZ5F6Wn5Bp6MCFINXhBsuoeKl3JN/Zt1gxHus9Fbhk7MiiHK4hmf9cg2oqGvnopiC6KgV910/CPQrGpFG+mguBxbVDTb0UVr7EzLTVrmDmod0u9at0T+Ltxztu1BtrBhvMSgkCeLwVKB6oiLEfTAEzxY/mKshXQ5DxlrcOB+ZK4ma/PIeOrfEVjecebDrM+Wxn6bbXr8aLfH2WrKu67Os8ty2xWC4gnUWg7jSIzOIwHYnsDUx/KesGhciqt+fWSTzyRA==\"");
//        String decrypt = AesEncryptionUtil.decrypt(x="D6pS8/TP70NMoSyDJjRDCYTIvvOpzIBRY4sdlF69yT409V8PwwYZxJ06iUtLecWDX446WILEJHZZfLP2sIMPqHRiJdiVgUq359it8bW8gJY=");
        //String decrypt = AesEncryptionUtil.decrypt(x="3JqF6BbmYis/2Qts4NlJq/x5BWR36IlgK3NbAgU8plY=");
        String decrypt = AesEncryptionUtil.decrypt("D6pS8/TP70NMoSyDJjRDCYTIvvOpzIBRY4sdlF69yT5jz5Y3Gcbop1O2R98XigzA8u6TvvJNBtDhgQ4pj+Mx3xYlyBijYO2LTB0UkMjP8mg=");
       // System.out.println("#加密串#" + encrypt);
        System.out.println("源串:"+x+"#解密串#" + decrypt+"|");
        String encrypt = AesEncryptionUtil.encrypt(decrypt);
       // System.out.println("\n加密后:\n"+encrypt);
       // System.out.println("\n解密后:\n"+AesEncryptionUtil.decrypt(encrypt));
    }
}

```
Rsa 加密升级

```
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
    public static void main(String[] args) {
        String key = "123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890";
//        String key = "1234567890";
        String encrypt = Rsa.encryptByPublic(key);
        System.out.println("加密前"+key);
        System.out.println("加密后"+encrypt);
        String result = Rsa.decryptByPublic(encrypt);
        System.out.println("解密后"+result);
    }
    public static final String SER_PUB = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC5Rar6q7W7lqkKn4iZdQAlPxGy\n" +
            "bZHbm6+c3i4sAsU0Q/z8MOZa2i1b4eD0AahpyJ6u2npqRpI3c90RhG2OtNjkbMos\n" +
            "iGwHPDzdSl/EKG7bihKAeuPWe5jcXDnh9UIkf4NorCylvqK+RkmMQop1hmnq4NXX\n" +
            "Vvd6Q+Dc3lGAVKNcNwIDAQAB";

    // public static final String RSA_PUBLICE = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDJ4/3VqHevhEUwMvmkY/DizPUF/s2lhyXHp1AhZhpzMjFUMGFIppJyHhcg3/r1jTHo+RJOjiT4D0g4yameVcp3ELmhyQArde4+gAG9762Zk4eDU+MM4AtOG7jSQk23BFWtYYEtwjXhGCX+L37sMqDdDJd6dLnKD+ghzswVEwAlgwIDAQAB";
    public static final String RSA_PUBLICE =
            "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDNQDs3peFeKvvl/lcOzatuEYiCV5bUF/xD/ldrBFswOQaDszxY5Up/sl4HGNRqMAomgAlOoNM1cXulmdFX7M6mzv2S48hT8GNJwPsG/dvaourQ6//EL/AC/Ue/t8nWCHToKct2ejbDShXKHLsqtsoh5Gb+PWjwdh1a1od+h3ZlZwIDAQAB";
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

```
