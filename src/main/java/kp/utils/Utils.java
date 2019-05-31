package kp.utils;

import java.nio.charset.StandardCharsets;
import java.util.Objects;

/**
 * Utilities.
 *
 */
public interface Utils {

	/**
	 * Converts a byte array to hex string.
	 * 
	 * @param block the block
	 * @return the result
	 */
	public static String bytesToHexAndUtf(byte[] block) {

		if (Objects.isNull(block)) {
			return "null";
		}
		return bytesToHexAndUtf(block, block.length);
	}

	/**
	 * Converts a byte array to hex string.
	 * 
	 * @param block     the block
	 * @param bytesRead the bytes read
	 * @return the result
	 */
	public static String bytesToHexAndUtf(byte[] block, int bytesRead) {

		StringBuffer utfBuf = new StringBuffer(), hexBuf = new StringBuffer();
		for (int i = 0; i < bytesRead; i++) {
			hexBuf.append(String.format("%02X ", block[i]));
			utfBuf.append(new String(block, i, 1, StandardCharsets.UTF_8));
		}
		for (int i = bytesRead; i < 8; i++) {
			hexBuf.append("   ");
		}
		String utfStr = utfBuf.toString();
		utfStr = utfStr.replaceAll("\n", " ");// 0A - line feed character
		utfStr = utfStr.replaceAll("\r", " ");// 0D - carriage-return character
		hexBuf.append("| ").append(utfStr);
		return hexBuf.toString();
	}
}