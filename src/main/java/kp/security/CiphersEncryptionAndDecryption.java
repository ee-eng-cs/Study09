package kp.security;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.ChaCha20ParameterSpec;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import kp.utils.Utils;

/*-
 * The AES cipher with GCM mode is an AEAD (Authenticated Encryption with Associated Data) cipher.
 * The AEAD cipher assures the confidentiality and the authenticity of data.
 *
 * Ciphers not researched here:
 * 
 * The 'Algorithm/Mode/Padding' combination "DES/CBC/PKCS5Padding" is outdated.
 * 
 * The ECB mode (the default in the JDK) should not be used for multiple data blocks. 
 */
/**
 * Researching ciphers with various algorithm, mode, and padding.
 * 
 */
public class CiphersEncryptionAndDecryption {

	private static final boolean VERBOSE = false;

	private static final String CLEARTEXT = "The quick brown fox jumps over the lazy dog.";

	/**
	 * Researches algorithm <b>AES</b> with mode <b>GCM</b>.<br>
	 * <ul>
	 * <li>AES: Advanced Encryption Standard
	 * <li>GCM: Galois Counter Mode
	 * </ul>
	 */
	public static void launchAES_GCM() {

		final String ALGORITHM_MODE_PADDING = "AES/GCM/NoPadding";
		final TransferBox transferBox = new TransferBox();
		try {
			byte[] encrypted = encryptAES(ALGORITHM_MODE_PADDING, transferBox);
			System.out.printf("Algorithm/Mode/Padding[%s], encrypted bytes length[%d]%n", ALGORITHM_MODE_PADDING,
					encrypted.length);
			System.out.printf("Transferring: secret[%s], initializationVector[%s]%n", transferBox.secret,
					transferBox.initializationVector);
			if (VERBOSE) {
				System.out.printf("encrypted bytes:%n%s%n", Utils.bytesToHexAndUtf(encrypted));
			}
			decryptAES(ALGORITHM_MODE_PADDING, transferBox, encrypted);
		} catch (InvalidKeyException | InvalidAlgorithmParameterException | NoSuchAlgorithmException
				| NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException e) {
			e.printStackTrace();
			System.exit(1);
		}
		System.out.println("- ".repeat(50));
	}

	/**
	 * Researches algorithm <b>AES</b> with mode <b>CBC</b>.<br>
	 * <ul>
	 * <li>AES: Advanced Encryption Standard
	 * <li>CBC: Cipher Block Chaining
	 * </ul>
	 */
	public static void launchAES_CBC() {

		final String ALGORITHM_MODE_PADDING = "AES/CBC/PKCS5PADDING";// PKCS5-style padding
		final TransferBox transferBox = new TransferBox();
		try {
			byte[] encrypted = encryptAES(ALGORITHM_MODE_PADDING, transferBox);
			System.out.printf("Algorithm/Mode/Padding[%s], encrypted bytes length[%d]%n", ALGORITHM_MODE_PADDING,
					encrypted.length);
			System.out.printf("Transferring: secret[%s], initializationVector[%s]%n", transferBox.secret,
					transferBox.initializationVector);
			decryptAES(ALGORITHM_MODE_PADDING, transferBox, encrypted);
		} catch (InvalidKeyException | InvalidAlgorithmParameterException | NoSuchAlgorithmException
				| NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException e) {
			e.printStackTrace();
			System.exit(1);
		}
		System.out.println("- ".repeat(50));
	}

	/**
	 * Researches algorithm <b>Blowfish</b>.
	 * 
	 */
	public static void launchBlowfish() {

		final TransferBoxBlowfish transferBoxBlowfish = new TransferBoxBlowfish();
		try {
			final byte[] encrypted = encryptBlowfish(transferBoxBlowfish);
			System.out.printf("Algorithm[Blowfish], encrypted bytes length[%d]%n", encrypted.length);
			decryptBlowfish(transferBoxBlowfish, encrypted);
		} catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException
				| BadPaddingException e) {
			e.printStackTrace();
			System.exit(1);
		}
		System.out.println("- ".repeat(50));
	}

	/**
	 * Researches algorithm <b>ChaCha20</b><br>
	 * This is a simple stream cipher with no authentication.
	 * 
	 */
	public static void launchChaCha20() {

		final TransferBox transferBox = new TransferBox();
		try {
			byte[] encrypted = encryptChaCha20(transferBox);
			System.out.printf("Algorithm[ChaCha20], encrypted bytes length[%d]%n", encrypted.length);
			decryptChaCha20(transferBox, encrypted);
		} catch (InvalidKeyException | InvalidAlgorithmParameterException | NoSuchAlgorithmException
				| NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException e) {
			e.printStackTrace();
			System.exit(1);
		}
		System.out.println("- ".repeat(50));
	}

	/**
	 * Researches algorithm <b>ChaCha20-Poly1305</b>.<br>
	 * This is a cipher in <b>AEAD</b> mode using the <b>Poly1305</b> authenticator
	 * 
	 */
	public static void launchChaCha20_Poly1305() {

		final TransferBox transferBox = new TransferBox();
		try {
			byte[] encrypted = encryptChaCha20_Poly1305(transferBox);
			System.out.printf("Algorithm[ChaCha20-Poly1305], encrypted bytes length[%d]%n", encrypted.length);
			decryptChaCha20_Poly1305(transferBox, encrypted);
		} catch (InvalidKeyException | InvalidAlgorithmParameterException | NoSuchAlgorithmException
				| NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException e) {
			e.printStackTrace();
			System.exit(1);
		}
		System.out.println("- ".repeat(50));
	}

	/**
	 * Encrypts the cleartext to temporary file and decrypts it from that file.
	 * 
	 */
	public static void encryptToFileAndDecryptFromFile() {

		try {
			final SecretKey secretKey = KeyGenerator.getInstance("AES").generateKey();
			final byte[] initializationVector = new byte[16];
			final Path encryptedFile = encryptToFile(secretKey, initializationVector);
			decryptFromFile(secretKey, initializationVector, encryptedFile);
		} catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException
				| InvalidAlgorithmParameterException | IOException e) {
			e.printStackTrace();
			System.exit(1);
		}
		System.out.println("- ".repeat(50));
	}

	/**
	 * Encrypts the clear text with the algorithm <b>AES</b>.
	 * 
	 * @param algorithmModePadding the algorithm/mode/padding combination
	 * @param transferBox          the transfer box
	 * @return the encrypted bytes
	 * @throws InvalidAlgorithmParameterException the security exception
	 * @throws InvalidKeyException                the security exception
	 * @throws NoSuchAlgorithmException           the security exception
	 * @throws BadPaddingException                the cryptography exception
	 * @throws IllegalBlockSizeException          the cryptography exception
	 * @throws NoSuchPaddingException             the cryptography exception
	 */
	private static byte[] encryptAES(String algorithmModePadding, TransferBox transferBox)
			throws InvalidAlgorithmParameterException, InvalidKeyException, NoSuchAlgorithmException,
			BadPaddingException, IllegalBlockSizeException, NoSuchPaddingException {

		final KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
		final SecretKey secretKey = keyGenerator.generateKey();

		// 16 bytes i.e. 128 bits - this is AES key length
		final byte[] initializationVector = new byte[16];
		SecureRandom.getInstanceStrong().nextBytes(initializationVector);

		final Cipher cipher = Cipher.getInstance(algorithmModePadding);
		final boolean modeFlag = algorithmModePadding.contains("/GCM/");
		final AlgorithmParameterSpec parameterSpec = modeFlag ? new GCMParameterSpec(128, initializationVector)
				: new IvParameterSpec(initializationVector);
		cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);

		transferBox.secret = new String(Base64.getEncoder().encodeToString(secretKey.getEncoded()));
		transferBox.initializationVector = new String(Base64.getEncoder().encodeToString(initializationVector));

		return cipher.doFinal(CLEARTEXT.getBytes(StandardCharsets.UTF_8));
	}

	/**
	 * Decrypts the encrypted bytes with the algorithm <b>AES</b>.
	 * 
	 * @param algorithmModePadding the algorithm/mode/padding combination
	 * @param transferBox          the transfer box
	 * @param encrypted            the encrypted bytes
	 * @throws InvalidAlgorithmParameterException the security exception
	 * @throws InvalidKeyException                the security exception
	 * @throws NoSuchAlgorithmException           the security exception
	 * @throws BadPaddingException                the cryptography exception
	 * @throws IllegalBlockSizeException          the cryptography exception
	 * @throws NoSuchPaddingException             the cryptography exception
	 */
	private static void decryptAES(String algorithmModePadding, TransferBox transferBox, byte[] encrypted)
			throws InvalidAlgorithmParameterException, InvalidKeyException, NoSuchAlgorithmException,
			BadPaddingException, IllegalBlockSizeException, NoSuchPaddingException {

		final SecretKey secretKey = new SecretKeySpec(Base64.getDecoder().decode(transferBox.secret), "AES");
		final byte[] initializationVector = Base64.getDecoder().decode(transferBox.initializationVector);

		final boolean modeFlag = algorithmModePadding.contains("/GCM/");
		final AlgorithmParameterSpec parameterSpec = modeFlag ? new GCMParameterSpec(128, initializationVector)
				: new IvParameterSpec(initializationVector);
		final Cipher cipher = Cipher.getInstance(algorithmModePadding);
		cipher.init(Cipher.DECRYPT_MODE, secretKey, parameterSpec);

		final byte[] decrypted = cipher.doFinal(encrypted);
		System.out.printf("decrypted text[%s]%n", new String(decrypted, StandardCharsets.UTF_8));
	}

	/**
	 * Encrypts the clear text with the algorithm <b>Blowfish</b>.
	 * 
	 * @param transferBoxBlowfish the transfer box
	 * @return the encrypted bytes
	 * @throws InvalidKeyException       the security exception
	 * @throws NoSuchAlgorithmException  the security exception
	 * @throws BadPaddingException       the cryptography exception
	 * @throws IllegalBlockSizeException the cryptography exception
	 * @throws NoSuchPaddingException    the cryptography exception
	 */
	private static byte[] encryptBlowfish(TransferBoxBlowfish transferBoxBlowfish) throws InvalidKeyException,
			NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException, NoSuchPaddingException {

		final String ALGORITHM = "Blowfish";
		final byte[] secretKeyEncoded = KeyGenerator.getInstance(ALGORITHM).generateKey().getEncoded();
		final Cipher cipher = Cipher.getInstance(ALGORITHM);
		cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(secretKeyEncoded, ALGORITHM));

		transferBoxBlowfish.secret = new String(Base64.getEncoder().encodeToString(secretKeyEncoded));
		return cipher.doFinal(CLEARTEXT.getBytes(StandardCharsets.UTF_8));
	}

	/**
	 * Decrypts the encrypted bytes with the algorithm <b>Blowfish</b>.
	 * 
	 * @param transferBoxBlowfish the transfer box
	 * @param encrypted           the encrypted bytes
	 * @throws InvalidKeyException       the security exception
	 * @throws NoSuchAlgorithmException  the security exception
	 * @throws BadPaddingException       the cryptography exception
	 * @throws IllegalBlockSizeException the cryptography exception
	 * @throws NoSuchPaddingException    the cryptography exception
	 */
	private static void decryptBlowfish(TransferBoxBlowfish transferBoxBlowfish, byte[] encrypted)
			throws InvalidKeyException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException,
			NoSuchPaddingException {

		final String ALGORITHM = "Blowfish";
		final Cipher cipher = Cipher.getInstance(ALGORITHM);
		final SecretKey secretKey = new SecretKeySpec(Base64.getDecoder().decode(transferBoxBlowfish.secret),
				ALGORITHM);
		cipher.init(Cipher.DECRYPT_MODE, secretKey);

		final byte[] decrypted = cipher.doFinal(encrypted);
		System.out.printf("decrypted text[%s]%n", new String(decrypted, StandardCharsets.UTF_8));
	}

	/**
	 * Encrypts the clear text with the algorithm <b>ChaCha20</b>.
	 * 
	 * @param transferBox the transfer box
	 * @return the encrypted bytes
	 * @throws InvalidAlgorithmParameterException the security exception
	 * @throws InvalidKeyException                the security exception
	 * @throws NoSuchAlgorithmException           the security exception
	 * @throws BadPaddingException                the cryptography exception
	 * @throws IllegalBlockSizeException          the cryptography exception
	 * @throws NoSuchPaddingException             the cryptography exception
	 */
	private static byte[] encryptChaCha20(TransferBox transferBox)
			throws InvalidAlgorithmParameterException, InvalidKeyException, NoSuchAlgorithmException,
			BadPaddingException, IllegalBlockSizeException, NoSuchPaddingException {

		final String ALGORITHM = "ChaCha20";
		final SecretKey secretKey = KeyGenerator.getInstance(ALGORITHM).generateKey();
		final byte[] initializationVector = new byte[12];
		SecureRandom.getInstanceStrong().nextBytes(initializationVector);
		final Cipher cipher = Cipher.getInstance(ALGORITHM);
		// Use a starting counter value of "7"
		final ChaCha20ParameterSpec parameterSpec = new ChaCha20ParameterSpec(initializationVector, 7);
		cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);

		transferBox.secret = new String(Base64.getEncoder().encodeToString(secretKey.getEncoded()));
		transferBox.initializationVector = new String(Base64.getEncoder().encodeToString(initializationVector));
		return cipher.doFinal(CLEARTEXT.getBytes(StandardCharsets.UTF_8));
	}

	/**
	 * Decrypts the encrypted bytes with the algorithm <b>ChaCha20</b>.
	 * 
	 * @param transferBox the transfer box
	 * @param encrypted   the encrypted bytes
	 * @throws InvalidAlgorithmParameterException the security exception
	 * @throws InvalidKeyException                the security exception
	 * @throws NoSuchAlgorithmException           the security exception
	 * @throws BadPaddingException                the cryptography exception
	 * @throws IllegalBlockSizeException          the cryptography exception
	 * @throws NoSuchPaddingException             the cryptography exception
	 */
	private static void decryptChaCha20(TransferBox transferBox, byte[] encrypted)
			throws InvalidAlgorithmParameterException, InvalidKeyException, NoSuchAlgorithmException,
			BadPaddingException, IllegalBlockSizeException, NoSuchPaddingException {

		final String ALGORITHM = "ChaCha20";
		final SecretKey secretKey = new SecretKeySpec(Base64.getDecoder().decode(transferBox.secret), ALGORITHM);
		final byte[] initializationVector = Base64.getDecoder().decode(transferBox.initializationVector);
		final Cipher cipher = Cipher.getInstance(ALGORITHM);
		final ChaCha20ParameterSpec parameterSpec = new ChaCha20ParameterSpec(initializationVector, 7);
		cipher.init(Cipher.DECRYPT_MODE, secretKey, parameterSpec);

		final byte[] decrypted = cipher.doFinal(encrypted);
		System.out.printf("decrypted text[%s]%n", new String(decrypted, StandardCharsets.UTF_8));
	}

	/**
	 * Encrypts the clear text with the algorithm <b>ChaCha20-Poly1305</b>.
	 * 
	 * @param transferBox the transfer box
	 * @return the encrypted bytes
	 * @throws InvalidAlgorithmParameterException the security exception
	 * @throws InvalidKeyException                the security exception
	 * @throws NoSuchAlgorithmException           the security exception
	 * @throws BadPaddingException                the cryptography exception
	 * @throws IllegalBlockSizeException          the cryptography exception
	 * @throws NoSuchPaddingException             the cryptography exception
	 */
	private static byte[] encryptChaCha20_Poly1305(TransferBox transferBox)
			throws InvalidAlgorithmParameterException, InvalidKeyException, NoSuchAlgorithmException,
			BadPaddingException, IllegalBlockSizeException, NoSuchPaddingException {

		final String ALGORITHM_KEY_GEN = "ChaCha20";
		final String ALGORITHM = "ChaCha20-Poly1305";
		final SecretKey secretKey = KeyGenerator.getInstance(ALGORITHM_KEY_GEN).generateKey();
		final byte[] initializationVector = new byte[12];
		SecureRandom.getInstanceStrong().nextBytes(initializationVector);
		final Cipher cipher = Cipher.getInstance(ALGORITHM);
		final AlgorithmParameterSpec parameterSpec = new IvParameterSpec(initializationVector);
		cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);

		transferBox.secret = new String(Base64.getEncoder().encodeToString(secretKey.getEncoded()));
		transferBox.initializationVector = new String(Base64.getEncoder().encodeToString(initializationVector));
		return cipher.doFinal(CLEARTEXT.getBytes(StandardCharsets.UTF_8));
	}

	/**
	 * Decrypts the encrypted bytes with the algorithm <b>ChaCha20-Poly1305</b>.
	 * 
	 * @param transferBox the transfer box
	 * @param encrypted   the encrypted bytes
	 * @throws InvalidAlgorithmParameterException the security exception
	 * @throws InvalidKeyException                the security exception
	 * @throws NoSuchAlgorithmException           the security exception
	 * @throws BadPaddingException                the cryptography exception
	 * @throws IllegalBlockSizeException          the cryptography exception
	 * @throws NoSuchPaddingException             the cryptography exception
	 */
	private static void decryptChaCha20_Poly1305(TransferBox transferBox, byte[] encrypted)
			throws InvalidAlgorithmParameterException, InvalidKeyException, NoSuchAlgorithmException,
			BadPaddingException, IllegalBlockSizeException, NoSuchPaddingException {

		final String ALGORITHM = "ChaCha20-Poly1305";
		final SecretKey secretKey = new SecretKeySpec(Base64.getDecoder().decode(transferBox.secret), ALGORITHM);
		final byte[] initializationVector = Base64.getDecoder().decode(transferBox.initializationVector);
		final Cipher cipher = Cipher.getInstance(ALGORITHM);
		final AlgorithmParameterSpec parameterSpec = new IvParameterSpec(initializationVector);
		cipher.init(Cipher.DECRYPT_MODE, secretKey, parameterSpec);

		final byte[] decrypted = cipher.doFinal(encrypted);
		System.out.printf("decrypted text[%s]%n", new String(decrypted, StandardCharsets.UTF_8));
	}

	/**
	 * Encrypts the cleartext to a temporary file.
	 * 
	 * @param secretKey            the secret key
	 * @param initializationVector the initialization vector
	 * @return the encrypted temporary file
	 * @throws InvalidKeyException                the security exception
	 * @throws InvalidAlgorithmParameterException the security exception
	 * @throws NoSuchAlgorithmException           the security exception
	 * @throws NoSuchPaddingException             the cryptography exception
	 * @throws IOException                        the I/O exception
	 */
	private static Path encryptToFile(SecretKey secretKey, byte[] initializationVector) throws InvalidKeyException,
			InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchPaddingException, IOException {

		SecureRandom.getInstanceStrong().nextBytes(initializationVector);

		final Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
		cipher.init(Cipher.ENCRYPT_MODE, secretKey, new GCMParameterSpec(128, initializationVector));

		final Path encryptedFile = Files.createTempFile("encrypted", ".txt");
		final FileOutputStream fileOutputStream = new FileOutputStream(encryptedFile.toFile());
		final CipherOutputStream cipherOutputStream = new CipherOutputStream(fileOutputStream, cipher);
		try (fileOutputStream; cipherOutputStream) {
			cipherOutputStream.write(CLEARTEXT.getBytes(StandardCharsets.UTF_8));
		}
		System.out.printf("Encrypted data were written to the file[%s]%n", encryptedFile);
		if (VERBOSE) {
			try (InputStream inputStream = Files.newInputStream(encryptedFile)) {
				System.out.printf("encrypted file content:%n%s%n",
						new String(inputStream.readAllBytes(), StandardCharsets.UTF_8));
			}
		}
		return encryptedFile;
	}

	/**
	 * Decrypts the encrypted bytes from a temporary file.
	 * 
	 * @param secretKey            the secret key
	 * @param initializationVector the initialization vector
	 * @param encryptedFile        the encrypted temporary file
	 * @throws InvalidKeyException                the security exception
	 * @throws InvalidAlgorithmParameterException the security exception
	 * @throws NoSuchAlgorithmException           the security exception
	 * @throws NoSuchPaddingException             the cryptography exception
	 * @throws IOException                        the I/O exception
	 */
	private static void decryptFromFile(SecretKey secretKey, byte[] initializationVector, Path encryptedFile)
			throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException,
			NoSuchPaddingException, IOException {

		final Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
		cipher.init(Cipher.DECRYPT_MODE, secretKey, new GCMParameterSpec(128, initializationVector));

		final FileInputStream fileInputStream = new FileInputStream(encryptedFile.toFile());
		final CipherInputStream cipherInputStream = new CipherInputStream(fileInputStream, cipher);
		try (fileInputStream; cipherInputStream) {
			final byte[] decrypted = cipherInputStream.readAllBytes();
			System.out.printf("decrypted text[%s]%n", new String(decrypted, StandardCharsets.UTF_8));
		}
	}

}

/**
 * The box with the the secret and the initialization vector.<br>
 * For transferring simulation from the sender to the receiver.
 * 
 */
class TransferBox {
	/**
	 * The secret key.
	 */
	String secret;
	/**
	 * The initialization vector.
	 */
	String initializationVector;
}

/**
 * The box with the the secret.<br>
 * For transferring simulation from the sender to the receiver. It is for with
 * Blowfish algorithm cipher.
 * 
 */
class TransferBoxBlowfish {
	/**
	 * The secret key.
	 */
	String secret;
}
