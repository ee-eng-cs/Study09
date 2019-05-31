package kp;

import kp.security.ChecksumsComputing;
import kp.security.CiphersEncryptionAndDecryption;
import kp.security.DigestsComputing;
import kp.security.KeysAndDigestsExchanging;
import kp.security.MacsComputing;
import kp.security.PasswordValidation;
import kp.security.SecureClass;
import kp.security.SignaturesSigning;
import kp.security.ecc.EllipticCurveCryptography;

/**
 * Main application for Study 09.<br>
 * The security research.
 *
 */
public class MainApp09 {
	private static final boolean ALL = true;
	private static final boolean ELLIPTIC_CURVE_CRYPTOGRAPHY = false;
	private static final boolean CHECKSUMS_COMPUTING = false;
	private static final boolean CIPHERS_ENCRYPTION_AND_DECRYPTION = false;
	private static final boolean DIGESTS_COMPUTING = false;
	private static final boolean KEYS_AND_DIGESTS_EXCHANGING = false;
	private static final boolean MACS_COMPUTING = false;
	private static final boolean SECURE_CLASS = false;
	private static final boolean SIGNATURES_SIGNING = false;
	private static final boolean PASSWORD_VALIDATION = false;

	/**
	 * The main method.
	 * 
	 * @param args the arguments
	 */
	public static void main(String[] args) {

		if (ALL || ELLIPTIC_CURVE_CRYPTOGRAPHY) {
			EllipticCurveCryptography.launch();
		}
		if (ALL || CHECKSUMS_COMPUTING) {
			ChecksumsComputing.launch();
		}
		if (ALL || CIPHERS_ENCRYPTION_AND_DECRYPTION) {
			CiphersEncryptionAndDecryption.launchAES_GCM();
		}
		if (ALL || CIPHERS_ENCRYPTION_AND_DECRYPTION) {
			CiphersEncryptionAndDecryption.launchAES_CBC();
		}
		if (ALL || CIPHERS_ENCRYPTION_AND_DECRYPTION) {
			CiphersEncryptionAndDecryption.launchBlowfish();
		}
		if (ALL || CIPHERS_ENCRYPTION_AND_DECRYPTION) {
			CiphersEncryptionAndDecryption.launchChaCha20();
		}
		if (ALL || CIPHERS_ENCRYPTION_AND_DECRYPTION) {
			CiphersEncryptionAndDecryption.launchChaCha20_Poly1305();
		}
		if (ALL || CIPHERS_ENCRYPTION_AND_DECRYPTION) {
			CiphersEncryptionAndDecryption.encryptToFileAndDecryptFromFile();
		}
		if (ALL || DIGESTS_COMPUTING) {
			DigestsComputing.launch();
		}
		if (ALL || KEYS_AND_DIGESTS_EXCHANGING) {
			KeysAndDigestsExchanging.launch();
		}
		if (ALL || MACS_COMPUTING) {
			MacsComputing.launch();
		}
		if (ALL || SECURE_CLASS) {
			SecureClass.newSecureClass().launch();
		}
		if (ALL || SIGNATURES_SIGNING) {
			SignaturesSigning.launch();
		}
		if (ALL || PASSWORD_VALIDATION) {
			PasswordValidation.launch();
		}
	}
}