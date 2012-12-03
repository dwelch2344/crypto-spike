package co.ntier.poc.crypto;

@SuppressWarnings("serial")
public class TomcatCryptoException extends RuntimeException {

	public TomcatCryptoException() {
		super();
	}

	public TomcatCryptoException(String message, Throwable cause) {
		super(message, cause);
	}

	public TomcatCryptoException(String message) {
		super(message);
	}

	public TomcatCryptoException(Throwable cause) {
		super(cause);
	}
}