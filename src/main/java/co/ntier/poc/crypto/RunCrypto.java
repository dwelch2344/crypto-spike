package co.ntier.poc.crypto;

import java.security.KeyPair;
import java.util.Scanner;

public class RunCrypto {

	public static void main(String[] args) throws Exception{
		KeyPair keypair = TomcatEncryptionUtils.retrieveKeyPair(null);
		System.out.println( TomcatEncryptionUtils.convertPublicKeyToString( keypair.getPublic() ));
		nl(3);

		Scanner scanner = new Scanner(System.in);
		System.out.print("Enter a value to encrypt: ");
		String line = scanner.nextLine();
		nl(3);

		String encrypted = TomcatEncryptionUtils.encryptValue(line, keypair.getPublic());
		System.out.println(encrypted);

		nl(3);
		String result = TomcatEncryptionUtils.decryptValue(encrypted, keypair.getPrivate());
		System.out.println("Decrypted: " + result);

		scanner.close();
	}

	public static void nl(int lines) {
		for( int i = 0; i < lines; i++) {
			System.out.println();
		}
	}

}
