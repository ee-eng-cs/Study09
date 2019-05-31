package kp.security.ecc;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import kp.utils.Utils;

/*- http://netnix.org/2015/04/19/aes-encryption-with-hmac-integrity-in-java/#more-544 */

/**
 * The Elliptic-Curve Cryptography.
 * 
 */
public class EllipticCurveCryptography {

	private static final String CLEARTEXT = "ĄĆĘ ŁŃÓ ŚŻŹ ąćę łńó śżź";

	/**
	 * Launches encrypted texts exchange.
	 * 
	 */
	public static void launch() {

		try {
			new EllipticCurveCryptography().launchWithExceptionsThrowing();
		} catch (Exception e) {
			e.printStackTrace();
			System.exit(1);
		}
		System.out.println("- ".repeat(50));
	}

	/**
	 * Launches encrypted texts exchange.
	 * 
	 * @throws NoSuchAlgorithmException           the security exception
	 * @throws NoSuchProviderException            the security exception
	 * @throws InvalidAlgorithmParameterException the security exception
	 * @throws InvalidKeySpecException            the security exception
	 * @throws InvalidKeyException                the security exception
	 * @throws SignatureException                 the security exception
	 * @throws IllegalBlockSizeException          the cryptography exception
	 * @throws BadPaddingException                the cryptography exception
	 * @throws NoSuchPaddingException             the cryptography exception
	 */
	private void launchWithExceptionsThrowing() throws NoSuchAlgorithmException, NoSuchProviderException,
			InvalidAlgorithmParameterException, InvalidKeySpecException, InvalidKeyException, SignatureException,
			IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException {

		/*-
		 * Initialize three boxes with personal data and
		 * a link between given person and its counterpart.
		 */
		final Map<Person, PrivateBox> privateBoxMap = new HashMap<>();
		final Map<Person, PublicStaticBox> publicStaticBoxMap = new HashMap<>();
		final Map<Person, PublicEphemeralBox> publicEphemeralBoxMap = new HashMap<>();
		final Map<Person, Person> counterpartMap = new HashMap<>();
		for (Person person : Person.values()) {
			privateBoxMap.put(person, new PrivateBox());
			publicStaticBoxMap.put(person, new PublicStaticBox());
			publicEphemeralBoxMap.put(person, new PublicEphemeralBox());
		}
		counterpartMap.put(Person.Alice, Person.Bob);
		counterpartMap.put(Person.Bob, Person.Alice);

		final KeyPairGenerator keyPairGenerator = initKeyPairGenerator();
		final MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
		/*
		 * Generate private keys and public static keys.
		 */
		for (Person person : Person.values()) {
			generateKeyPairECDSA(privateBoxMap.get(person), publicStaticBoxMap.get(person), keyPairGenerator);
			System.out.format("Person[%1$5s], public ECDSA SHA-256 hash[%2$x]%n", person.name(),
					new BigInteger(1, messageDigest.digest(publicStaticBoxMap.get(person).publicKeyECDSA)));
		}
		System.out.println("→ → →          Session start                ← ← ←");
		/*-
		 Generate public ephemeral keys.
		 
		 Ephemeral keys: a new public/private key pair per session.
		 A public-key system has the property of forward secrecy
		 if it generates one random secret key per session.
		 */
		for (Person person : Person.values()) {
			generateKeyPairECDH(privateBoxMap.get(person), publicEphemeralBoxMap.get(person), keyPairGenerator);
			signPublicKeyECDH_WithPrivateKeyECDSA(privateBoxMap.get(person), publicEphemeralBoxMap.get(person));
			System.out.format("Person[%1$5s], public ECDH  SHA-256 hash[%2$x]%n", person.name(),
					new BigInteger(1, messageDigest.digest(publicEphemeralBoxMap.get(person).publicKeyECDH)));
		}
		for (Person person : Person.values()) {
			final Person counterpart = counterpartMap.get(person);
			verifyCounterpartPublicKeys(person.name(), publicStaticBoxMap.get(counterpart),
					publicEphemeralBoxMap.get(counterpart));
			computeSecretKey(person.name(), privateBoxMap.get(person), publicEphemeralBoxMap.get(counterpart));
		}
		/*-
		Person and its counterpart have the same authenticated 128-bit shared secret
		which they use for AES-GCM.
		*/
		System.out.println("▼ ▼ ▼          Cleartext exchange           ▼ ▼ ▼");
		for (Person person : Person.values()) {
			/*-
			The person encrypts the text for its counterpart using his/her shared secret.
			*/
			final String ciphertext = encrypt(CLEARTEXT, privateBoxMap.get(person).sharedSecret);
			System.out.format("Person[%5s], ciphertext[%s]%n", person.name(), ciphertext);
			/*-
			The counterpart decrypts the text from person using his/her shared secret.
			*/
			final Person counterpart = counterpartMap.get(person);
			final String cleartext = decrypt(ciphertext, privateBoxMap.get(counterpart).sharedSecret);
			System.out.format("Person[%5s], cleartext[%s]%n", counterpart.name(), cleartext);
		}
		System.out.println("▲ ▲ ▲                                       ▲ ▲ ▲");
	}

	/**
	 * Initializes the key pair generator.<br>
	 * Generates keypairs for the Elliptic Curve algorithm.
	 * 
	 * @return the key pair generator
	 * @throws NoSuchAlgorithmException           the security exception
	 * @throws NoSuchProviderException            the security exception
	 * @throws InvalidAlgorithmParameterException the security exception
	 */
	private KeyPairGenerator initKeyPairGenerator()
			throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {

		final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
		keyPairGenerator.initialize(new ECGenParameterSpec("secp256r1"));
		return keyPairGenerator;
	}

	/**
	 * Generates the Elliptic-Curve Digital Signature Algorithm key pair.
	 * 
	 * @param privateBox       the private box
	 * @param publicStaticBox  the public static box
	 * @param keyPairGenerator the key pair generator
	 * @throws NoSuchAlgorithmException           the security exception
	 * @throws InvalidAlgorithmParameterException the security exception
	 * @throws NoSuchProviderException            the security exception
	 */
	private void generateKeyPairECDSA(PrivateBox privateBox, PublicStaticBox publicStaticBox,
			KeyPairGenerator keyPairGenerator)
			throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchProviderException {

		/*-
		Person:
		1. generates a static ECDSA Key Pair
		2. securely stores her/his ECDSA Private Key on disk using symmetric encryption
		3. sends his/her ECDSA Public Key to counterpart person
		*/
		final KeyPair keyPair = keyPairGenerator.generateKeyPair();
		privateBox.privateKeyECDSA = keyPair.getPrivate();
		publicStaticBox.publicKeyECDSA = keyPair.getPublic().getEncoded();
	}

	/**
	 * Generates the Elliptic-Curve Diffie-Hellman key pair.
	 * 
	 * @param privateBox         the private box
	 * @param publicEphemeralBox the public ephemeral box
	 * @param keyPairGenerator   the key pair generator
	 * @throws InvalidKeyException                the security exception
	 * @throws NoSuchAlgorithmException           the security exception
	 * @throws NoSuchProviderException            the security exception
	 * @throws SignatureException                 the security exception
	 * @throws InvalidAlgorithmParameterException the security exception
	 */
	private void generateKeyPairECDH(PrivateBox privateBox, PublicEphemeralBox publicEphemeralBox,
			KeyPairGenerator keyPairGenerator) throws InvalidKeyException, NoSuchAlgorithmException,
			NoSuchProviderException, SignatureException, InvalidAlgorithmParameterException {
		/*-
		Person:
		1. generates an ephemeral ECDH Key Pair
		*/
		final KeyPair keyPair = keyPairGenerator.genKeyPair();
		privateBox.privateKeyECDH = keyPair.getPrivate();
		publicEphemeralBox.publicKeyECDH = keyPair.getPublic().getEncoded();
	}

	/**
	 * Signs the Elliptic-Curve Diffie-Hellman public key with<br>
	 * the Elliptic-Curve Digital Signature Algorithm private key.
	 * 
	 * @param privateBox         the private box
	 * @param publicEphemeralBox the public ephemeral box
	 * @throws InvalidKeyException      the security exception
	 * @throws NoSuchAlgorithmException the security exception
	 * @throws NoSuchProviderException  the security exception
	 * @throws SignatureException       the security exception
	 */
	private void signPublicKeyECDH_WithPrivateKeyECDSA(PrivateBox privateBox, PublicEphemeralBox publicEphemeralBox)
			throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException {
		/*-
		Person:
		1. signs her/his ephemeral ECDH Public Key with his/her static ECDSA Private Key
		2. sends her/his ephemeral ECDH Public Key with the ECDSA Signature to counterpart
		*/
		final Signature signatureForSigning = Signature.getInstance("SHA256withECDSA");
		signatureForSigning.initSign(privateBox.privateKeyECDSA);
		signatureForSigning.update(publicEphemeralBox.publicKeyECDH);
		publicEphemeralBox.signatureECDSA = signatureForSigning.sign();
	}

	/**
	 * Verifies counterpart public keys.
	 * 
	 * @param name                          the name of the person
	 * @param counterpartPublicStaticBox    the counterpart public static box
	 * @param counterpartPublicEphemeralBox the counterpart public ephemeral box
	 * @throws InvalidKeyException      the security exception
	 * @throws NoSuchAlgorithmException the security exception
	 * @throws NoSuchProviderException  the security exception
	 * @throws SignatureException       the security exception
	 * @throws InvalidKeySpecException  the security exception
	 */
	private void verifyCounterpartPublicKeys(String name, PublicStaticBox counterpartPublicStaticBox,
			PublicEphemeralBox counterpartPublicEphemeralBox) throws InvalidKeyException, NoSuchAlgorithmException,
			NoSuchProviderException, SignatureException, InvalidKeySpecException {

		final PublicKey verifiedPublicKeyECDSA = verifyCounterpartPublicKeyECDSA(counterpartPublicStaticBox);
		final MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
		System.out.format("Cntrp.[%1$5s], public ECDSA SHA-256 hash[%2$x] verified%n", name,
				new BigInteger(1, messageDigest.digest(verifiedPublicKeyECDSA.getEncoded())));
		verifyCounterpartPublicKeyECDH(counterpartPublicEphemeralBox, verifiedPublicKeyECDSA);
	}

	/**
	 * Verifies counterpart Elliptic-Curve Digital Signature Algorithm public key.
	 * 
	 * @param counterpartPublicStaticBox the counterpart public static box
	 * @return the verified public ECDSA key
	 * @throws InvalidKeySpecException  the security exception
	 * @throws NoSuchAlgorithmException the security exception
	 */
	private PublicKey verifyCounterpartPublicKeyECDSA(PublicStaticBox counterpartPublicStaticBox)
			throws InvalidKeySpecException, NoSuchAlgorithmException {
		/*-
		Person:
		1. recovers counterpart's ECDSA Public Key and verifies SHA-256 Hash Offline
		2. once verified, person should store this verified key (verifiedPublicECDSAKey) for future authentication
		*/
		final KeyFactory keyFactory = KeyFactory.getInstance("EC");
		final KeySpec keySpec = new X509EncodedKeySpec(counterpartPublicStaticBox.publicKeyECDSA);
		final PublicKey verifiedPublicECDSAKey = keyFactory.generatePublic(keySpec);
		return verifiedPublicECDSAKey;
	}

	/**
	 * Verifies counterpart Elliptic-Curve Diffie-Hellman public key.
	 * 
	 * @param counterpartPublicEphemeralBox the counterpart public ephemeral box
	 * @param verifiedPublicKeyECDSA        the verified public key ECDSA
	 * @throws InvalidKeyException      the security exception
	 * @throws NoSuchAlgorithmException the security exception
	 * @throws NoSuchProviderException  the security exception
	 * @throws SignatureException       the security exception
	 */
	private void verifyCounterpartPublicKeyECDH(PublicEphemeralBox counterpartPublicEphemeralBox,
			PublicKey verifiedPublicKeyECDSA)
			throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException {

		/*-
		Person:
		1. verifies counterpart's ephemeral ECDH Public Key and ECDSA Signature
		   using counterpart's trusted ECDSA Public Key (verifiedPublicKeyECDSA)
		*/
		final Signature signatureForVerification = Signature.getInstance("SHA256withECDSA");
		signatureForVerification.initVerify(verifiedPublicKeyECDSA);
		signatureForVerification.update(counterpartPublicEphemeralBox.publicKeyECDH);

		if (!signatureForVerification.verify(counterpartPublicEphemeralBox.signatureECDSA)) {
			System.out.println("Error: person can't verify signature of counterpart's Public Key ECDH");
			System.exit(0);
		}
	}

	/**
	 * Computes the Shared Secret Key by combining two keys:
	 * <ul>
	 * <li>the local private key
	 * <li>the received public key
	 * </ul>
	 * 
	 * @param name                          the name of the person
	 * @param privateBox                    the private box
	 * @param counterpartPublicEphemeralBox the counterpart public ephemeral box
	 * @throws InvalidKeyException      the security exception
	 * @throws NoSuchAlgorithmException the security exception
	 * @throws InvalidKeySpecException  the security exception
	 */
	private void computeSecretKey(String name, PrivateBox privateBox, PublicEphemeralBox counterpartPublicEphemeralBox)
			throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException {
		/*-
		Person:
		1. generates Secret Key using
		   a. person's ECDH Private Key and
		   b. counterpart's verified ECDH Public Key
		*/
		final KeyFactory keyFactory = KeyFactory.getInstance("EC");
		// convert received byte array back into Diffie-Hellman Public Key
		final KeySpec keySpec = new X509EncodedKeySpec(counterpartPublicEphemeralBox.publicKeyECDH);
		final PublicKey counterpartPublicKeyECDH = keyFactory.generatePublic(keySpec);
		/*
		 * Key agreement is a protocol by which 2 or more parties can establish the same
		 * cryptographic keys, without having to exchange any secret information.
		 */
		final KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH");
		keyAgreement.init(privateBox.privateKeyECDH);
		keyAgreement.doPhase(counterpartPublicKeyECDH, true);
		final MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
		/*- Use the first 128 bits (i.e. 16 bytes)
		 *  of the SHA-256 hash of the 256-bit shared secret key */
		privateBox.sharedSecret = Arrays.copyOfRange(messageDigest.digest(keyAgreement.generateSecret()), 0, 16);

		System.out.format("Person[%5s], shared secret[%s]%n", name, Utils.bytesToHexAndUtf(privateBox.sharedSecret));
	}

	/**
	 * Encrypts using the AES-GCM<br>
	 * (algorithm: Advanced Encryption Standard, mode: Galois/Counter Mode).
	 * 
	 * @param cleartext the cleartext
	 * @param secret    the secret
	 * @return the encrypted
	 * @throws NoSuchAlgorithmException           the security exception
	 * @throws IllegalBlockSizeException          the cryptography exception
	 * @throws BadPaddingException                the cryptography exception
	 * @throws InvalidKeyException                the security exception
	 * @throws InvalidAlgorithmParameterException the security exception
	 * @throws NoSuchPaddingException             the cryptography exception
	 */
	private String encrypt(String cleartext, byte[] secret) throws NoSuchAlgorithmException, IllegalBlockSizeException,
			BadPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, NoSuchPaddingException {

		final byte[] initializationVector = new byte[12];// 96 bits
		SecureRandom.getInstanceStrong().nextBytes(initializationVector);

		final SecretKeySpec secretKey = new SecretKeySpec(secret, "AES");
		// transformation name: "algorithm/mode/padding"
		final Cipher cipherForEncryption = Cipher.getInstance("AES/GCM/NoPadding");
		cipherForEncryption.init(Cipher.ENCRYPT_MODE, secretKey, new GCMParameterSpec(128, initializationVector));
		final byte[] es = cipherForEncryption.doFinal(cleartext.getBytes(StandardCharsets.UTF_8));

		final byte[] os = new byte[12 + es.length];
		System.arraycopy(initializationVector, 0, os, 0, 12);
		System.arraycopy(es, 0, os, 12, es.length);
		final String encrypted = Base64.getEncoder().encodeToString(os);
		return encrypted;
	}

	/**
	 * Decrypts using the AES-GCM<br>
	 * (algorithm: Advanced Encryption Standard, mode: Galois/Counter Mode).
	 * 
	 * @param encrypted the encrypted
	 * @param secret    the secret
	 * @return the clear text
	 * @throws NoSuchAlgorithmException           the security exception
	 * @throws NoSuchPaddingException             the cryptography exception
	 * @throws InvalidKeyException                the security exception
	 * @throws InvalidAlgorithmParameterException the security exception
	 * @throws IllegalBlockSizeException          the cryptography exception
	 * @throws BadPaddingException                the cryptography exception
	 */
	private String decrypt(String encrypted, byte[] secret) throws NoSuchAlgorithmException, NoSuchPaddingException,
			InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {

		final byte[] os = Base64.getDecoder().decode(encrypted);
		// confirming 'encrypted' contains at least the Initialization Vector
		// (12 bytes) and the Authentication Tag (16 bytes)
		if (os.length <= 28) {
			System.out.printf("Error: too small cleartext length[%d].%n", os.length);
			System.exit(0);
		}
		final byte[] initializationVector = Arrays.copyOfRange(os, 0, 12);
		final byte[] es = Arrays.copyOfRange(os, 12, os.length);

		final SecretKeySpec secretKey = new SecretKeySpec(secret, "AES");
		final Cipher cipherForDecryption = Cipher.getInstance("AES/GCM/NoPadding");
		cipherForDecryption.init(Cipher.DECRYPT_MODE, secretKey, new GCMParameterSpec(128, initializationVector));
		final String decrypted = new String(cipherForDecryption.doFinal(es), StandardCharsets.UTF_8);
		return decrypted;
	}

	/**
	 * The fictional characters.
	 * 
	 */
	private enum Person {
		Alice, Bob
	}

	/**
	 * The box with the private data. Those data are never exchanged.
	 * 
	 */
	private class PrivateBox {
		/**
		 * Elliptic-Curve Digital Signature Algorithm private key.
		 */
		PrivateKey privateKeyECDSA;
		/**
		 * Elliptic-Curve Diffie-Hellman private key.
		 */
		PrivateKey privateKeyECDH;

		/**
		 * The secret shared between given person and its counterpart.
		 */
		byte[] sharedSecret;
	}

	/**
	 * The box with the public static data.<br>
	 * Those data were exchanged offline between the person and its counterpart.
	 * 
	 */
	private class PublicStaticBox {
		/**
		 * Elliptic-Curve Digital Signature Algorithm public static key.
		 */
		byte[] publicKeyECDSA;
	}

	/**
	 * The box with the public ephemeral data.<br>
	 * These data are exchanged in session between the person and its counterpart.
	 */
	private class PublicEphemeralBox {
		/**
		 * Elliptic-Curve Diffie-Hellman public ephemeral key.
		 */
		byte[] publicKeyECDH;
		/**
		 * Elliptic-Curve Digital Signature Algorithm ephemeral signature.
		 */
		byte[] signatureECDSA;
	}

}