package security.security;


import java.io.UnsupportedEncodingException;

import security.security.util.AESUtils;

/**
 * Created by rocko on 15-11-12.
 */
public class AESCipherStrategy extends CipherStrategy {

	private String key;

	public AESCipherStrategy(String key) {
		this.key = key;
	}

	@Override
	public String encrypt(String content) {
		byte[] encryptByte = new byte[0];
		try {
			encryptByte = AESUtils.encryptData(content.getBytes(CHARSET), key);
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}
		return encodeConvert(encryptByte);
	}

	@Override
	public String decrypt(String encryptContent) {
		byte[] encrypByte = decodeConvert(encryptContent);
		byte[] decryptByte = AESUtils.decryptData(encrypByte, key);
		String result = "";
		try {
			result = new String(decryptByte, CHARSET);
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}

		return result;
	}
}
