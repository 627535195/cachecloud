package com.sohu.cache.util;

import org.apache.commons.lang.Validate;

import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * 封装各种Hash算法的工具类
 * 
 * SHA-1, 安全性较高, 返回byte[](可用Encodes进一步被编码为Hex, Base64)
 * 
 * 性能优化，不每次获取MessageDigest
 * 
 * 支持带salt并且进行迭代达到更高的安全性.
 *
 */
public abstract class SHA1Util {

	public static final Charset UTF_8 = Charset.forName("UTF-8");

	private static final MessageDigest SHA_1_DIGEST = getSha1Digest();

	private static SecureRandom random = new SecureRandom();

	////////////////// SHA1 ///////////////////
	/**
	 * 对输入字符串进行sha1散列.
	 */
	public static byte[] sha1(byte[] input) {
		return digest(input, SHA_1_DIGEST, null, 1);
	}

	/**
	 * 对输入字符串进行sha1散列, 编码默认为UTF8.
	 */
	public static byte[] sha1(String input) {
		return digest(input.getBytes(UTF_8), SHA_1_DIGEST, null, 1);
	}

	/**
	 * 对输入字符串进行sha1散列，带salt达到更高的安全性.
	 */
	public static byte[] sha1(byte[] input, byte[] salt) {
		return digest(input, SHA_1_DIGEST, salt, 1);
	}

	/**
	 * 对输入字符串进行sha1散列，带salt达到更高的安全性.
	 */
	public static byte[] sha1(String input, byte[] salt) {
		return digest(input.getBytes(UTF_8), SHA_1_DIGEST, salt, 1);
	}

	/**
	 * 对输入字符串进行sha1散列，带salt而且迭代达到更高更高的安全性.
	 * 
	 * @see #generateSalt(int)
	 */
	public static byte[] sha1(byte[] input, byte[] salt, int iterations) {
		return digest(input, SHA_1_DIGEST, salt, iterations);
	}

	/**
	 * 对输入字符串进行sha1散列，带salt而且迭代达到更高更高的安全性.
	 * 
	 * @see #generateSalt(int)
	 */
	public static byte[] sha1(String input, byte[] salt, int iterations) {
		return digest(input.getBytes(UTF_8), SHA_1_DIGEST, salt, iterations);
	}

	/**
	 * 用SecureRandom生成随机的byte[]作为salt.
	 *
	 * @param numBytes salt数组的大小
	 */
	public static byte[] generateSalt(int numBytes) {
		Validate.isTrue(numBytes > 0, "numBytes argument must be a positive integer (1 or larger)", numBytes);

		byte[] bytes = new byte[numBytes];
		random.nextBytes(bytes);
		return bytes;
	}

	private static MessageDigest getSha1Digest() {
		try {
			return MessageDigest.getInstance("SHA-1");
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(
					"unexpected exception creating MessageDigest instance for [SHA-1]", e);
		}
	}

	/**
	 * 对字符串进行散列, 支持md5与sha1算法.
	 */
	private static byte[] digest(byte[] input, MessageDigest digest, byte[] salt, int iterations) {
		// 带盐
		if (salt != null) {
			digest.update(salt);
		}

		// 第一次散列
		byte[] result = digest.digest(input);

		// 如果迭代次数>1，进一步迭代散列
		for (int i = 1; i < iterations; i++) {
			digest.reset();
			result = digest.digest(result);
		}

		return result;
	}

}
