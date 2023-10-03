package SecuredConversationBetweenClientAndServer;

import java.security.NoSuchAlgorithmException;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class SecretKeyGenerator {
	SecretKey secretkey;
	
	public SecretKeyGenerator() {
		KeyGenerator keygen;
		try {
			keygen = KeyGenerator.getInstance("AES");
			keygen.init(256);
			secretkey = keygen.generateKey();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			System.out.println("Unexpected Error occured");
		}
		
	}
}
