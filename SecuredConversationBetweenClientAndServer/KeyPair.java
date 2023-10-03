package SecuredConversationBetweenClientAndServer;

import java.security.*;

public class KeyPair {
	java.security.PublicKey publickey;
	java.security.PrivateKey privatekey;
	
	KeyPair() {
	try {
		KeyPairGenerator keygen = KeyPairGenerator.getInstance("RSA");
		keygen.initialize(2048);
		
		java.security.KeyPair keypair = keygen.genKeyPair();
		
		publickey = keypair.getPublic();
		privatekey = keypair.getPrivate();
		
	} catch (NoSuchAlgorithmException e) {
		System.out.println("Error Occured");
	}
	
	}
}
