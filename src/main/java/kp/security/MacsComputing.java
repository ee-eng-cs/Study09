package kp.security;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;

import kp.utils.Utils;

/*-
 * The algorithms not researched here are 'HmacMD5' and 'HmacSHA1':
 *  - the 'MD5' has been replaced with the 'SHA'
 *  - the 'SHA-1' message digest is flawed
 *  
 * The MACs are used between two parties that share a secret key
 * in order to validate information transmitted between these parties.
 * A MAC mechanism that is based on cryptographic hash functions is referred to as HMAC. 
 */
/**
 * Computing the Message Authentication Codes with different algorithms.
 *
 */
public class MacsComputing {
	private static final boolean VERBOSE = false;

	private static final boolean USE_RANDOM = true;

	private static final String CONTENT = "The quick brown fox jumps over the lazy dog.";

	private static final String[] MAC_ALGORITHMS = { "HmacSHA256", "HmacSHA512" };

	/**
	 * Launches key generation and MAC computing.
	 * 
	 */
	public static void launch() {

		try {
			for (int i = 0; i < MAC_ALGORITHMS.length; i++) {
				final KeyGenerator keyGenerator = KeyGenerator.getInstance(MAC_ALGORITHMS[i]);
				if (USE_RANDOM) {
					keyGenerator.init(1024, new SecureRandom());
				}
				final SecretKey secretKey = keyGenerator.generateKey();
				final byte[] macBytesComputedAlice = computeMac(MAC_ALGORITHMS[i], secretKey);
				final byte[] macBytesComputedBob = computeMac(MAC_ALGORITHMS[i], secretKey);
				if (VERBOSE) {
					System.out.printf("MAC bytes:%n%s%n", Utils.bytesToHexAndUtf(macBytesComputedAlice));
				}
				System.out.printf("MAC algorithm[%10s], length[%d], MACs are equal[%b]%n", MAC_ALGORITHMS[i],
						macBytesComputedAlice.length, Arrays.equals(macBytesComputedAlice, macBytesComputedBob));
			}
			System.out.println("- ".repeat(50));
		} catch (InvalidKeyException | NoSuchAlgorithmException e) {
			e.printStackTrace();
			System.exit(1);
		}
	}

	/**
	 * Computes the message authentication code.
	 * 
	 * @param macAlgorithm the MAC algorithm
	 * @param secretKey    the secret key
	 * @return the MAC data tag
	 * @throws NoSuchAlgorithmException the security exception
	 * @throws InvalidKeyException      the security exception
	 */
	private static byte[] computeMac(String macAlgorithm, SecretKey secretKeyArr)
			throws NoSuchAlgorithmException, InvalidKeyException {

		final Mac mac = Mac.getInstance(macAlgorithm);
		mac.init(secretKeyArr);
		mac.update(CONTENT.getBytes());
		final byte[] macBytes = mac.doFinal();
		return macBytes;
	}
}
