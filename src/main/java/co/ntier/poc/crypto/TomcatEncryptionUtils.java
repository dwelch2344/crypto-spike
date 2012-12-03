package co.ntier.poc.crypto;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.StringTokenizer;
import java.util.logging.Logger;

import javax.crypto.Cipher;

public class TomcatEncryptionUtils {
	public static final String CIPHER_TEXT_PREFIX = "{encrypted}";

	private static final String PRIVATE_KEY_ENCODED_HEADER = "---------Private Key PKCS8 Encoded---------";

	private static final String PUBLIC_KEY_ENCODED_HEADER = "---------Public Key X.509 Encoded---------";

	private static final String KEY_ALGORITHM = "RSA";

	private static final String DEFAULT_ALGORITHM = "RSA/ECB/PKCS1Padding";

	public static final String PUBLIC_KEY_FOOTER = "=====================Tomcat Public Key End===================";

	public static final String PUBLIC_KEY_HEADER = "====================Tomcat Public Key Begin==================";


	static final String DEFAULT_FOLDER = ".ntier";

	static final String DEFAULT_FILE = File.separator + DEFAULT_FOLDER + File.separator + "tomcatCfg.key";

	static final String DEFAULT_DIRECTORY = File.separator + DEFAULT_FOLDER;

	static final Logger logger = Logger.getLogger(TomcatEncryptionUtils.class.getName());

	/**
	 * Loads up or creates a KeyPair optionally given the location of a generated Key File.
	 *
	 * <ul>
	 * <li>If the location is a Key File then simply load the KeyPair and return.</li>
	 * <li>If no file exists at the location specified then create a new Key File in the location specified.</li>
	 * <li>If the location is null then create or load a Key File from the default location of ${user.home}/.stack/tomcatCfg.key</li>
	 * <ul>
	 * @param location The location of a Tomcat Key File.  A Stack custom key file used to store a generated Key.
	 * @return A loaded or generated Key File.
	 */
	public static KeyPair retrieveKeyPair(File location) {
		if (location == null) {
			String userHome = System.getProperty("user.home");
			location = new File(userHome + DEFAULT_FILE);
		}
		if (!location.exists()) {
			logger.info("Generating new Tomcat KeyPair and storing it in: "+location);
			return createKeyPair(location);
		}
		logger.info("Loading Tomcat KeyPair from: "+location);
		KeyPair keyPair = getKeyPairFromKeyFile(location);
		return keyPair;
	}

	/**
	 * Loads up a KeyPair from a KeyStore at the specified location.  All parameters are required.
	 * @param location The file location of a KeyStore.  Must be of the format of the System Default KeyStore (see KeyStore.getDefaultType()).
	 * @param alias The alias of the key.
	 * @param keyStorePassword The password to the keystore.
	 * @param keyPassword The password to the key.
	 * @return A loaded KeyPair from the KeyStore.
	 */
	public static KeyPair retrieveKeyPair(File location, String alias, char[] keyStorePassword, char[] keyPassword) {
		if(location == null || alias == null || keyStorePassword == null || keyPassword == null) {
			throw new IllegalArgumentException("Failed to load key from KeyStore.  Location, alias, keyStorePassword, and keyPassword must all be specified.");
		}
		logger.info("Attempting to load Tomcat KeyStore from file '"+location+"' with alias '"+alias+"'.");
		KeyPair keyPair = getKeyPairFromKeyStore(location, alias, keyStorePassword, keyPassword);
		if (keyPair == null) {
			throw new TomcatCryptoException("Unable to obtain KeyPair from KeyStore '" + location + "'.  Please check your specified Alias and passwords.");
		}
		return keyPair;
	}

	private static KeyPair getKeyPairFromKeyFile(File location) {
		ObjectInputStream inputStream = null;
		try {
			try {
				inputStream = new ObjectInputStream(new FileInputStream(location));
				byte[] publicHeader = new byte[PUBLIC_KEY_ENCODED_HEADER.getBytes("UTF-8").length];
				inputStream.read(publicHeader);
				if(!Arrays.equals(publicHeader, PUBLIC_KEY_ENCODED_HEADER.getBytes("UTF-8"))) {
					throw new TomcatCryptoException("Unable to load KeyPair from location '"+location.getAbsolutePath()+"'.  File appears to be corrupt.");
				}
				int publicKeyLength = inputStream.readInt();
				byte[] encodedPublicKey = new byte[publicKeyLength];
				inputStream.readFully(encodedPublicKey);
				byte[] privateHeader = new byte[PRIVATE_KEY_ENCODED_HEADER.getBytes("UTF-8").length];
				inputStream.read(privateHeader);
				if(!Arrays.equals(privateHeader, PRIVATE_KEY_ENCODED_HEADER.getBytes("UTF-8"))) {
					throw new TomcatCryptoException("Unable to load KeyPair from location '"+location.getAbsolutePath()+"'.  File appears to be corrupt.");
				}
				int privateKeyLength = inputStream.readInt();
				byte[] encodedPrivateKey = new byte[privateKeyLength];
				inputStream.readFully(encodedPrivateKey);

				// Generate KeyPair.
				KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
				X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(
						encodedPublicKey);
				PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

				PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(
						encodedPrivateKey);
				PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);
				return new KeyPair(publicKey, privateKey);
			}
			catch (Exception e) {
				throw new TomcatCryptoException("Unable to load keyfile from '" + location + "'.  File may be corrupted.  Delete the file to create a new key or fix your key file.", e);
			}
		}
		finally {
			if (inputStream != null) {
				try {
					inputStream.close();
				}
				catch (IOException e) { /* Do Nothing */
				}
			}
		}
	}

	private static KeyPair getKeyPairFromKeyStore(File location, String alias, char[] keyStorePassword,
			char[] keyPassword) {
		InputStream inputStream = null;
		try {
			try {
				KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
				inputStream = new FileInputStream(location);
				keyStore.load(inputStream, keyStorePassword);
				if (alias == null || "".equals(alias.trim())) {
					throw new IllegalArgumentException("Alias required for KeyStore located at: " + location);
				}
				if (!keyStore.containsAlias(alias)) {
					throw new IllegalStateException("Alias '" + alias + "' not found in KeyStore located at: "
							+ location);
				}
				Key key = keyStore.getKey(alias, keyPassword);
				if (!(key instanceof PrivateKey)) {
					throw new IllegalStateException("Key found with alias '" + alias
							+ "' is not a PrivateKey found in KeyStore located at: " + location);
				}
				PrivateKey privateKey = (PrivateKey) key;
				Certificate certificate = keyStore.getCertificate(alias);
				KeyPair keyPair = new KeyPair(certificate.getPublicKey(), privateKey);
				return keyPair;
			}
			catch (Exception e) {
				throw new TomcatCryptoException("Unable to load keystore from '" + location + "'", e);
			}
		}
		finally {
			if (inputStream != null) {
				try {
					inputStream.close();
				}
				catch (IOException e) { /* Do Nothing */
				}
			}
		}
	}

	private static KeyPair createKeyPair(File location) {
		KeyPairGenerator kpg;
		try {
			kpg = KeyPairGenerator.getInstance(KEY_ALGORITHM);
		}
		catch (NoSuchAlgorithmException e) {
			throw new TomcatCryptoException("Unable to create RSA KeyPairGenerator.", e);
		}
		kpg.initialize(2048);
		KeyPair kp = kpg.genKeyPair();

		ObjectOutputStream stream = null;
		try {
			location.getParentFile().mkdirs();
			location.createNewFile();
			stream = new ObjectOutputStream(new FileOutputStream(location));
			stream.write(new String(PUBLIC_KEY_ENCODED_HEADER).getBytes("UTF-8"));
			// Store Public Key.
			X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(
					kp.getPublic().getEncoded());
			stream.writeInt(x509EncodedKeySpec.getEncoded().length);
			stream.write(x509EncodedKeySpec.getEncoded());
			stream.write(new String(PRIVATE_KEY_ENCODED_HEADER).getBytes("UTF-8"));
			// Store Private Key.
			PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(
					kp.getPrivate().getEncoded());
			stream.writeInt(pkcs8EncodedKeySpec.getEncoded().length);
			stream.write(pkcs8EncodedKeySpec.getEncoded());
			stream.close();
			return kp;
		}
		catch (IOException e) {
			throw new TomcatCryptoException("Failed to create key file.", e);
		} finally {
			if(stream != null) {
				try {
					stream.close();
				} catch(Exception e) {
					/* Do Nothing */
				}
			}
		}
	}

	/**
	 * Converts a Public key into a custom String representation of that PublicKey.
	 * @param publicKey
	 * @return
	 */
	public static String convertPublicKeyToString(PublicKey publicKey) {
		X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(publicKey.getEncoded());
		StringBuilder builder = new StringBuilder();
		builder.append(PUBLIC_KEY_HEADER);
		char[] base64Key = Base64.byteArrayToBase64(x509EncodedKeySpec.getEncoded()).toCharArray();
		for (int loop = 0; loop < base64Key.length; loop++) {
			if (loop % PUBLIC_KEY_HEADER.length() == 0) {
				builder.append('\n');
			}
			builder.append(base64Key[loop]);
		}
		builder.append("\n");
		builder.append(PUBLIC_KEY_FOOTER);
		return builder.toString();
	}

	/**
	 * Converts a String into a Public Key.  The String must be of the same format returned from convertPublicKeyToString().
	 * @param string
	 * @return
	 */
	public static PublicKey convertStringToPublicKey(String string) {
		if (!string.contains(PUBLIC_KEY_HEADER) || !string.contains(PUBLIC_KEY_FOOTER)) {
			throw new TomcatCryptoException(
					"Unable to import public key from string.  String doesn't contain valid header or footer.");
		}
		try {
			StringTokenizer tokenizer = new StringTokenizer(string, "\n");
			StringBuilder builder = new StringBuilder();
			while (tokenizer.hasMoreElements()) {
				String line = tokenizer.nextToken().trim();
				if(line != null && line.startsWith(PUBLIC_KEY_HEADER)) {
					line = line.replace(PUBLIC_KEY_HEADER, "");
				}
				if(line != null && line.endsWith(PUBLIC_KEY_FOOTER)) {
					line = line .replace(PUBLIC_KEY_FOOTER, "");
				}
				if (PUBLIC_KEY_HEADER.equals(line) || PUBLIC_KEY_FOOTER.equals(line) || "".equals(line)) {
					continue;
				}
				builder.append(line);
			}
			X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(Base64.base64ToByteArray(builder.toString()));

			KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
			return keyFactory.generatePublic(x509EncodedKeySpec);
		}
		catch (Exception e) {
			throw new TomcatCryptoException(
					"Unable to import public key from string.  Please check the String to ensure it is valid.", e);
		}
	}

	/**
	 * Decrypts a value encrypted using "RSA/ECB/PKCS1Padding" with the given PrivateKey.
	 * @param value
	 * @param key
	 * @return
	 */
	public static String decryptValue(String value, PrivateKey key) {
		try {
			Cipher cipher = Cipher.getInstance(DEFAULT_ALGORITHM);
			cipher.init(Cipher.DECRYPT_MODE, key);
			return new String(cipher.doFinal(Base64.base64ToByteArray(value)), "UTF-8");
		}
		catch (Exception e) {
			throw new TomcatCryptoException("Unexpected error attempting to decrypt value.", e);
		}
	}

	/**
	 * Encrypts a String using "RSA/ECB/PKCS1Padding" with the given PublicKey.
	 * @param value
	 * @param key
	 * @return
	 */
	public static String encryptValue(String value, PublicKey key) {
		try {
			Cipher cipher = Cipher.getInstance(DEFAULT_ALGORITHM);
			cipher.init(Cipher.ENCRYPT_MODE, key);
			return Base64.byteArrayToBase64(cipher.doFinal(value.getBytes("UTF-8")));
		}
		catch (Exception e) {
			throw new TomcatCryptoException("Unexpected error attempting to encrypt value.", e);
		}
	}
}

