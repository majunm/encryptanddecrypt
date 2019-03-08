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
