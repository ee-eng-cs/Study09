package kp.security;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import kp.utils.Utils;

/*-
 * A digest has two properties:
 * - It should be computationally infeasible to find two messages that hash to the same value.
 * - The digest should not reveal anything about the input that was used to generate it.
 *
 * 'SHA-3' is a subset of the broader cryptographic primitive family 'Keccak'.
 * 
 * The algorithms not researched here are 'MD5' and 'SHA-1':
 *  - the 'MD5' has been replaced with the 'SHA'
 *  - the 'SHA-1' message digest is flawed
 */
/**
 * Computing the digests with different algorithms.
 *
 */
public class DigestsComputing {

	private static final boolean VERBOSE = false;

	private static final String CONTENT = "The quick brown fox jumps over the lazy dog.";

	private static final String[] MESSAGE_DIGEST_ALGORITHMS = { /*-*/
			"SHA-256", "SHA-512", /*- members of the 'SHA-2' family */
			"SHA3-224", "SHA3-256", "SHA3-384", "SHA3-512"/*- members of the 'SHA-3' family */
	};

	/**
	 * Computes two digests and compares them for equality.
	 * 
	 */
	public static void launch() {
		try {
			for (String messageDigestAlgorithm : MESSAGE_DIGEST_ALGORITHMS) {
				final byte[] digestBytesAlice = computeDigest(messageDigestAlgorithm);
				final byte[] digestBytesBob = computeDigest(messageDigestAlgorithm);
				if (VERBOSE) {
					System.out.printf("digest bytes:%n%s%n", Utils.bytesToHexAndUtf(digestBytesAlice));
				}
				System.out.printf("message digest algorithm[%8s], length[%d], digests are equal[%b]%n",
						messageDigestAlgorithm, digestBytesAlice.length,
						MessageDigest.isEqual(digestBytesAlice, digestBytesBob));
			}
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			System.exit(1);
		}
		System.out.println("- ".repeat(50));
	}

	/**
	 * Computes the digest.
	 * 
	 * @param messageDigestAlgorithm the algorithm of a message digest
	 * @return the digest bytes
	 * @throws NoSuchAlgorithmException the security exception
	 */
	private static byte[] computeDigest(String messageDigestAlgorithm) throws NoSuchAlgorithmException {

		final MessageDigest messageDigest = MessageDigest.getInstance(messageDigestAlgorithm);
		messageDigest.update(CONTENT.getBytes());
		return messageDigest.digest();
	}
}
