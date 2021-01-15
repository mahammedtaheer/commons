package io.mosip.kernel.keymanager.hsm.impl;

import java.security.Key;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import javax.crypto.SecretKey;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import io.mosip.kernel.core.keymanager.model.CertificateParameters;
import io.mosip.kernel.core.keymanager.spi.KeyStore;
import io.mosip.kernel.keymanager.hsm.constant.KeymanagerConstant;


/**
 * HSM Keymanager implementation based on OpenDNSSEC that handles and stores
 * its cryptographic keys via the PKCS#11 interface. This is a software
 * implementation of a generic cryptographic device. SoftHSM can work with other
 * cryptographic device because of the PKCS#11 interface.
 * 
 * @author Dharmesh Khandelwal
 * @since 1.0.0
 *
 */
@ConfigurationProperties(prefix = "mosip.kernel.keymanager.hsm")
@Component
public class KeyStoreImpl implements KeyStore, InitializingBean {


	/**
	 * The type of keystore, e.g. PKCS11, PKCS12, JCE
	 */
	@Value("${mosip.kernel.keymanager.hsm.keystore-type:PKCS11}")
	private String keystoreType;

	/**
	 * Path of HSM PKCS11 config file or the Keystore in caes of bouncy castle
	 * provider
	 */
	@Value("${mosip.kernel.keymanager.hsm.config-path}")
	private String configPath;

	/**
	 * The passkey for Keystore
	 */
	@Value("${mosip.kernel.keymanager.hsm.keystore-pass:\"\"}")
	private String keystorePass;

	/**
	 * Symmetric key algorithm Name
	 */
	@Value("${mosip.kernel.keygenerator.symmetric-algorithm-name}")
	private String symmetricKeyAlgorithm;

	/**
	 * Symmetric key length
	 */
	@Value("${mosip.kernel.keygenerator.symmetric-key-length}")
	private int symmetricKeyLength;

	/**
	 * Asymmetric key algorithm Name
	 */
	@Value("${mosip.kernel.keygenerator.asymmetric-algorithm-name}")
	private String asymmetricKeyAlgorithm;

	/**
	 * Asymmetric key length
	 */
	@Value("${mosip.kernel.keygenerator.asymmetric-key-length}")
	private int asymmetricKeyLength;

	/**
	 * Certificate Signing Algorithm
	 * 
	 */
	@Value("${mosip.kernel.certificate.sign.algorithm:SHA256withRSA}")
	private String signAlgorithm;
	

	private Map<String, String> jceProperties;

	private KeyStore keyStore = null;

	@Override
	public void afterPropertiesSet() throws Exception {

		if (Objects.isNull(jceProperties)) {
			jceProperties = new HashMap<String, String>();
		}
		addAlgorithmProperties();
		if (keystoreType.equals(KeymanagerConstant.KEYSTORE_TYPE_PKCS11)) {
			addPKCS11Properties();
			keyStore = new io.mosip.kernel.keymanager.hsm.impl.PKCS11KeyStoreImpl(jceProperties);
			return;
	}
	}

	private void addAlgorithmProperties() {
		jceProperties.put(KeymanagerConstant.SYM_KEY_ALGORITHM, symmetricKeyAlgorithm);
		jceProperties.put(KeymanagerConstant.SYM_KEY_SIZE, Integer.toString(symmetricKeyLength));
		jceProperties.put(KeymanagerConstant.ASYM_KEY_ALGORITHM, asymmetricKeyAlgorithm);
		jceProperties.put(KeymanagerConstant.ASYM_KEY_SIZE, Integer.toString(asymmetricKeyLength));
		jceProperties.put(KeymanagerConstant.CERT_SIGN_ALGORITHM, signAlgorithm);
	}

	private void addPKCS11Properties() {
		jceProperties.put(KeymanagerConstant.CONFIG_FILE_PATH, configPath);
		jceProperties.put(KeymanagerConstant.PKCS11_KEYSTORE_PASSWORD, keystorePass);
		}
		/*
	 * (non-Javadoc)
	 * 
	 * @see io.mosip.kernel.core.keymanager.spi.SofthsmKeystore#getAllAlias()
	 */
	@Override
	public List<String> getAllAlias() {
		return keyStore.getAllAlias();
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * io.mosip.kernel.core.keymanager.spi.SofthsmKeystore#getKey(java.lang.String)
	 */
	@Override
	public Key getKey(String alias) {
		return keyStore.getKey(alias);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * io.mosip.kernel.core.keymanager.spi.SofthsmKeystore#getAsymmetricKey(java.
	 * lang.String)
	 */
	@SuppressWarnings("findsecbugs:HARD_CODE_PASSWORD")
	@Override
	public PrivateKeyEntry getAsymmetricKey(String alias) {
		return keyStore.getAsymmetricKey(alias);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * io.mosip.kernel.core.keymanager.spi.SofthsmKeystore#getPrivateKey(java.lang.
	 * String)
	 */
	@Override
	public PrivateKey getPrivateKey(String alias) {
		return keyStore.getPrivateKey(alias);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * io.mosip.kernel.core.keymanager.spi.SofthsmKeystore#getPublicKey(java.lang.
	 * String)
	 */
	@Override
	public PublicKey getPublicKey(String alias) {
		return keyStore.getPublicKey(alias);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * io.mosip.kernel.core.keymanager.spi.SofthsmKeystore#getCertificate(java.lang.
	 * String)
	 */
	@Override
	public X509Certificate getCertificate(String alias) {
		return (X509Certificate) keyStore.getCertificate(alias);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * io.mosip.kernel.core.keymanager.spi.SofthsmKeystore#getSymmetricKey(java.lang
	 * .String)
	 */
	@SuppressWarnings("findsecbugs:HARD_CODE_PASSWORD")
	@Override
	public SecretKey getSymmetricKey(String alias) {
		return keyStore.getSymmetricKey(alias);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see io.mosip.kernel.core.keymanager.spi.SofthsmKeystore#deleteKey(java.lang.
	 * String)
	 */
	@Override
	public void deleteKey(String alias) {
		keyStore.deleteKey(alias);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * io.mosip.kernel.core.keymanager.spi.SofthsmKeystore#storeAsymmetricKey(java.
	 * security.KeyPair, java.lang.String)
	 */
	@SuppressWarnings("findsecbugs:HARD_CODE_PASSWORD")
	@Override
	public void generateAndStoreAsymmetricKey(String alias, String signKeyAlias, CertificateParameters certParams) {
		keyStore.generateAndStoreAsymmetricKey(alias, signKeyAlias, certParams);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * io.mosip.kernel.core.keymanager.spi.SofthsmKeystore#storeSymmetricKey(javax.
	 * crypto.SecretKey, java.lang.String)
	 */
	@SuppressWarnings("findsecbugs:HARD_CODE_PASSWORD")
	@Override
	public void generateAndStoreSymmetricKey(String alias) {
		keyStore.generateAndStoreSymmetricKey(alias);
	}

	@Override
	public void storeCertificate(String alias, PrivateKey privateKey, Certificate certificate) {
		keyStore.storeCertificate(alias, privateKey, certificate);
	}

	@Override
	public String getKeystoreProviderName() {
		return keyStore.getKeystoreProviderName();
	}

	public void setJce(Map<String, String> jce) {
		this.jceProperties = jce;
		}

	
}
