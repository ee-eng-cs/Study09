package kp.security;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.KeyAgreement;

import kp.utils.Utils;

/*-
 * Key agreement is a protocol by which 2 or more parties can establish
 * the same cryptographic keys, without having to exchange any secret information.
 * 
 * It is more common in cryptography to exchange certificates
 * containing public keys rather than the keys themselves.
 * 
 * The  keys negotiated by the parties:
 *  - shared AES cipher key
 *  - HMAC shared secret
 */
/**
 * The simulation of a data exchange over an insecure net.<br>
 * Only the public keys and the digest bytes are exchanged there.
 * 
 */
public class KeysAndDigestsExchanging {

	private static final boolean VERBOSE = false;

	private static KeyPair keyPairAlice = null;
	private static KeyPair keyPairBob = null;

	/**
	 * Launches the exchange simulation.
	 * 
	 */
	public static void launch() {

		try {
			computeKeyPairs();
			showKeysInBase64(keyPairAlice);

			final byte[] encodedPublicKeyAlice = keyPairAlice.getPublic().getEncoded();
			final byte[] digestBytesBob = receiveAlicePublicKeyAndSendBobDigest(encodedPublicKeyAlice);

			final byte[] encodedPublicKeyBob = keyPairBob.getPublic().getEncoded();
			final byte[] digestBytesAlice = receiveBobPublicKeyAndSendAliceDigest(encodedPublicKeyBob);

			System.out.printf("Exchanged digests are equal[%b]%n",
					MessageDigest.isEqual(digestBytesBob, digestBytesAlice));
			if (VERBOSE) {
				System.out.printf("Alice encoded private key%n%s%n",
						Utils.bytesToHexAndUtf(keyPairAlice.getPrivate().getEncoded()));
				System.out.printf("Alice encoded public key%n%s%n",
						Utils.bytesToHexAndUtf(keyPairAlice.getPublic().getEncoded()));
				System.out.printf("Alice digest bytes%n%s%n", Utils.bytesToHexAndUtf(digestBytesAlice));
			}
		} catch (InvalidKeyException | NoSuchAlgorithmException | InvalidAlgorithmParameterException
				| IllegalStateException | InvalidKeySpecException e) {
			e.printStackTrace();
			System.exit(1);
		}
		System.out.println("- ".repeat(50));
	}

	/**
	 * Computes the key pair for Alice and Bob.
	 * 
	 * @throws NoSuchAlgorithmException           the security exception
	 * @throws InvalidAlgorithmParameterException the security exception
	 */
	private static void computeKeyPairs() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {

		final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
		keyPairGenerator.initialize(new ECGenParameterSpec("secp256r1"), SecureRandom.getInstanceStrong());
		keyPairAlice = keyPairGenerator.generateKeyPair();
		keyPairBob = keyPairGenerator.generateKeyPair();
	}

	/**
	 * Receives Alice public key and sends Bob digest bytes.
	 * 
	 * @param encodedPublicKeyAlice the received encoded public key
	 * @throws NoSuchAlgorithmException           the security exception
	 * @throws InvalidKeySpecException            the security exception
	 * @throws IllegalStateException              the illegal state exception
	 * @throws InvalidKeyException                the security exception
	 * @throws InvalidAlgorithmParameterException the security exception
	 */
	private static byte[] receiveAlicePublicKeyAndSendBobDigest(byte[] encodedPublicKeyAlice)
			throws NoSuchAlgorithmException, InvalidKeyException, IllegalStateException, InvalidKeySpecException,
			InvalidAlgorithmParameterException {

		final byte[] encodedPrivateKey = keyPairBob.getPrivate().getEncoded();
		final byte[] sharedSecret = computeSharedSecret(encodedPrivateKey, encodedPublicKeyAlice);
		final byte[] digestBytes = MessageDigest.getInstance("SHA-256").digest(sharedSecret);

		System.out.printf("Bob   shared secret length[%d], message digest length[%d]%n", sharedSecret.length,
				digestBytes.length);
		return digestBytes;
	}

	/**
	 * Receives Bob public key and sends Alice digest bytes.
	 * 
	 * @param encodedPublicKeyBob the received encoded public key
	 * @throws NoSuchAlgorithmException           the security exception
	 * @throws InvalidKeySpecException            the security exception
	 * @throws IllegalStateException              the illegal state exception
	 * @throws InvalidKeyException                the security exception
	 * @throws InvalidAlgorithmParameterException the security exception
	 */
	private static byte[] receiveBobPublicKeyAndSendAliceDigest(byte[] encodedPublicKeyBob)
			throws NoSuchAlgorithmException, InvalidKeyException, IllegalStateException, InvalidKeySpecException,
			InvalidAlgorithmParameterException {

		final byte[] encodedPrivateKey = keyPairAlice.getPrivate().getEncoded();
		final byte[] sharedSecret = computeSharedSecret(encodedPrivateKey, encodedPublicKeyBob);
		final byte[] digestBytes = MessageDigest.getInstance("SHA-256").digest(sharedSecret);

		System.out.printf("Alice shared secret length[%d], message digest length[%d]%n", sharedSecret.length,
				digestBytes.length);
		return digestBytes;
	}

	/**
	 * Computes the shared secret.
	 * 
	 * @param encodedPrivateKey the encoded private key
	 * @param encodedPublicKey  the encoded public key
	 * @return the shared secret
	 * @throws NoSuchAlgorithmException the security exception
	 * @throws InvalidKeyException      the security exception
	 * @throws IllegalStateException    the illegal state exception
	 * @throws InvalidKeySpecException  the security exception
	 */
	private static byte[] computeSharedSecret(byte[] encodedPrivateKey, byte[] encodedPublicKey)
			throws NoSuchAlgorithmException, InvalidKeyException, IllegalStateException, InvalidKeySpecException {

		final KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH");
		final PrivateKey privateKey = KeyFactory.getInstance("EC")
				.generatePrivate(new PKCS8EncodedKeySpec(encodedPrivateKey));
		keyAgreement.init(privateKey);
		final PublicKey publicKey = KeyFactory.getInstance("EC")
				.generatePublic(new X509EncodedKeySpec(encodedPublicKey));
		keyAgreement.doPhase(publicKey, true);
		final byte[] sharedSecret = keyAgreement.generateSecret();
		return sharedSecret;
	}

	/**
	 * Shows keys in URL and Filename safe <b>Base64</b>.
	 * 
	 * @param keyPair the key pair
	 */
	private static void showKeysInBase64(KeyPair keyPair) {

		final byte[] encodedPrivateKey = keyPair.getPrivate().getEncoded();
		final byte[] encodedPublicKey = keyPair.getPublic().getEncoded();
		System.out.printf("encoded private key length[%3d], encoded public key length[%3d]%n", encodedPrivateKey.length,
				encodedPublicKey.length);
		final String base64Priv = Base64.getUrlEncoder().encodeToString(encodedPrivateKey);
		final String base64Pub = Base64.getUrlEncoder().encodeToString(encodedPublicKey);
		System.out.printf("private key changed to Base64 (length[%3d]):%n [%s]%n", base64Priv.length(), base64Priv);
		System.out.printf("public  key changed to Base64 (length[%3d]):%n [%s]%n", base64Pub.length(), base64Pub);
	}
}
