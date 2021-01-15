package io.mosip.kernel.keymanager.hsm.constant;

/**
 * Constants for Softhsm Keystore
 * 
 * @author Dharmesh Khandelwal
 * @since 1.0.0
 *
 */
public final class KeymanagerConstant {

	/**
	 * Private constructor for SofthsmKeystoreConstant
	 */
	private KeymanagerConstant() {
	}

	/**
	 * String constant for dot
	 */
	public static final String DOT = ".";
	/**
	 * String constant for signature algorithm
	 */
	public static final String SIGNATURE_ALGORITHM = "SHA256withRSA";


	public static final String KEYSTORE_TYPE_PKCS11 = "PKCS11";

	public static final String KEYSTORE_TYPE_PKCS12 = "PKCS12";

	public static final String SYM_KEY_ALGORITHM = "SYM_KEY_ALGORITHM";

	public static final String SYM_KEY_SIZE = "SYM_KEY_SIZE";

	public static final String ASYM_KEY_ALGORITHM = "ASYM_KEY_ALGORITHM";

	public static final String ASYM_KEY_SIZE = "ASYM_KEY_SIZE";

	public static final String CERT_SIGN_ALGORITHM = "CERT_SIGN_ALGORITHM";

	public static final String CONFIG_FILE_PATH = "CONFIG_FILE_PATH";

	public static final String PKCS11_KEYSTORE_PASSWORD = "PKCS11_KEYSTORE_PASSWORD";

}
