package kp.security;

import java.util.zip.Adler32;
import java.util.zip.CRC32;
import java.util.zip.CRC32C;
import java.util.zip.Checksum;

/**
 * Computing the checksums.
 *
 */
public class ChecksumsComputing {

	private static final String CONTENT = "The quick brown fox jumps over the lazy dog.";

	// CRC32C (Castagnoli) is implemented in hardware in Intel CPUs
	private static final Checksum[] CHECKSUM = { new CRC32C(), new CRC32(), new Adler32() };

	/**
	 * Computes the checksums with different algorithms.
	 * 
	 */
	public static void launch() {

		for (int i = 0; i < CHECKSUM.length; i++) {
			CHECKSUM[i].reset();
			CHECKSUM[i].update(CONTENT.getBytes(), 0, CONTENT.length());
			System.out.printf("checksum algorithm[%7s], value[%10d]%n", CHECKSUM[i].getClass().getSimpleName(),
					CHECKSUM[i].getValue());
		}
		System.out.println("- ".repeat(50));
	}
}
