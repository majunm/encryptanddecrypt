package security.security;


import java.io.UnsupportedEncodingException;

import security.security.util.DESUtils;

public class DESCipherStrategy extends CipherStrategy {

	private String key;// 解密密码

	/**
	 * @param key
	 *            加解密的 key
	 */
	public DESCipherStrategy(String key) {
		this.key = key;
	}

	@Override
	public String encrypt(String content) {
		byte[] encryptByte = null;
		try {
			encryptByte = DESUtils.encrypt(content.getBytes(CHARSET), key);
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}
		return encodeConvert(encryptByte);
	}

	@Override
	public String decrypt(String encryptContent) {
		byte[] encrypByte = decodeConvert(encryptContent);
		byte[] decryptByte = DESUtils.decrypt(encrypByte, key);
		String result = "";
		try {
			result = new String(decryptByte, CHARSET);
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}

		return result;
	}

}
