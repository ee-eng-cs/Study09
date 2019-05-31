package kp.security;

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.util.LinkedHashMap;
import java.util.Map;

import kp.utils.Utils;

/*-
 * The algorithms not researched here are 'MD5withRSA' and 'SHA1withRSA':
 *  - the 'MD5' has been replaced with the 'SHA'
 *  - the 'SHA-1' message digest is flawed
 * 
 * The 'SHA-2' variants: 'SHA-224', 'SHA-256', 'SHA-384', 'SHA-512'.
 * 
 * For the 'SHA3-*withECDSA' algorithms was raised the exception 'Signature not available'.
 */
/**
 * Signing the signatures with different algorithms.
 *
 */
public class SignaturesSigning {

	private static final boolean VERBOSE = false;
	private static final boolean USE_RANDOM = true;
	private static final String CONTENT = "The quick brown fox jumps over the lazy dog.";

	/**
	 * Launches the keys generation, the signature signing and verification.
	 * 
	 */
	public static void launch() {

		final Map<String, String> SIGNATURE_ALGORITHMS_MAP = new LinkedHashMap<>();
		SIGNATURE_ALGORITHMS_MAP.put("SHA512withRSA", "RSA");
		SIGNATURE_ALGORITHMS_MAP.put("SHA256withDSA", "DSA");
		SIGNATURE_ALGORITHMS_MAP.put("SHA512withECDSA", "EC");
		try {
			for (String signatureAlgorithm : SIGNATURE_ALGORITHMS_MAP.keySet()) {
				final String keyPairAlgorithm = SIGNATURE_ALGORITHMS_MAP.get(signatureAlgorithm);
				final KeyPair keyPair = generateKeyPair(keyPairAlgorithm);
				final byte[] signatureBytes = signSignature(signatureAlgorithm, keyPair.getPrivate());
				if (VERBOSE) {
					System.out.printf("signature bytes:%n%s%n", Utils.bytesToHexAndUtf(signatureBytes));
				}
				final boolean verified = verifySignature(signatureAlgorithm, keyPair.getPublic(), signatureBytes);
				System.out.printf(
						"signature algorithm[%15s], key pair algorithm[%3s], signature bytes length[%3d], verified[%b]%n",
						signatureAlgorithm, SIGNATURE_ALGORITHMS_MAP.get(signatureAlgorithm), signatureBytes.length,
						verified);
			}
		} catch (InvalidKeyException | NoSuchAlgorithmException | SignatureException e) {
			e.printStackTrace();
			System.exit(1);
		}
		System.out.println("- ".repeat(50));
	}

	/**
	 * Generates key pair.
	 * 
	 * @param keyPairAlgorithm the name of key pair algorithm
	 * @return the key pair
	 * @throws NoSuchAlgorithmException the security exception
	 */
	private static KeyPair generateKeyPair(String keyPairAlgorithm) throws NoSuchAlgorithmException {

		final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(keyPairAlgorithm);
		if (USE_RANDOM) {
			keyPairGenerator.initialize("EC".equals(keyPairAlgorithm) ? 256 : 1024, new SecureRandom());
		}
		return keyPairGenerator.generateKeyPair();
	}

	/**
	 * Signs the signature.
	 * 
	 * @param signatureAlgorithm the name of signature algorithm
	 * @param privateKey         the private key
	 * @return the signature bytes
	 * @throws NoSuchAlgorithmException the security exception
	 * @throws SignatureException       the security exception
	 * @throws InvalidKeyException      the security exception
	 */
	private static byte[] signSignature(String signatureAlgorithm, PrivateKey privateKey)
			throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {

		final Signature signSignature = Signature.getInstance(signatureAlgorithm);
		signSignature.initSign(privateKey);
		signSignature.update(CONTENT.getBytes());
		return signSignature.sign();
	}

	/**
	 * Verifies the signatures.
	 * 
	 * @param signatureAlgorithm the name of signature algorithm
	 * @param publicKey          the public key
	 * @param signatureBytes     the signature bytes
	 * @return the verification result
	 * @throws NoSuchAlgorithmException the security exception
	 * @throws InvalidKeyException      the security exception
	 * @throws SignatureException       the security exception
	 */
	private static boolean verifySignature(String signatureAlgorithm, PublicKey publicKey, byte[] signatureBytes)
			throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {

		final Signature verifySignature = Signature.getInstance(signatureAlgorithm);
		verifySignature.initVerify(publicKey);
		verifySignature.update(CONTENT.getBytes());
		return verifySignature.verify(signatureBytes);
	}
}