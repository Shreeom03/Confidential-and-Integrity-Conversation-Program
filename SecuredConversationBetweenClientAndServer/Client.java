package SecuredConversationBetweenClientAndServer;
import java.io.*;
import java.net.*;
import java.security.*;
import java.util.Base64;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;

public class Client {
	
	public static void main(String args[]) throws Exception {
		KeyPair pair = new KeyPair();
		
		final String serverAddress = "I.P. Address"; //Here goes server's ip address to be connected
        final int serverPort = 12345;

        try (Socket socket = new Socket(serverAddress, serverPort)) {
            System.out.println("Connected to the server at " + serverAddress + ":" + serverPort);

            BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            PrintWriter out = new PrintWriter(socket.getOutputStream(), true);

            BufferedReader userInput = new BufferedReader(new InputStreamReader(System.in));
            
            out.println(publicKeyToString(pair.publickey));
            
            
            SecretKey secretkey = decryptAESKeyWithRSAPrivateKey(in.readLine(), pair.privatekey);
            
            String message;
            String response = "";
            while (response != null) {
                System.out.print("Your message: ");
                message = userInput.readLine();
                message = encryptWithAES(message,secretkey);
                String s = Integer.toString(message.hashCode());

                out.println(message);
                out.println(s);

                String str = in.readLine();
                if(str == null) {
                	System.out.println("BYE");
                	break;
                }
                response = decryptMessage(str ,secretkey);
                
                String hash = in.readLine();
                if(Integer.parseInt(hash) != response.hashCode()) {
                	System.out.println("Invalid Message");
                	return;
                }
                System.out.println("Server says: " + response);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
	}
	
	public static SecretKey decryptAESKeyWithRSAPrivateKey(String encryptedAESKeyString, PrivateKey privateKey) throws Exception {
        byte[] encryptedAESKeyBytes = Base64.getDecoder().decode(encryptedAESKeyString);
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedAESKeyBytes = cipher.doFinal(encryptedAESKeyBytes);
        return new SecretKeySpec(decryptedAESKeyBytes, "AES");
    }
	
	public static String publicKeyToString(PublicKey publicKey) {
        byte[] publicKeyBytes = publicKey.getEncoded();
        return Base64.getEncoder().encodeToString(publicKeyBytes);
    }
	
	public static String encryptWithAES(String plaintext, SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);

        byte[] encryptedBytes = cipher.doFinal(plaintext.getBytes("UTF-8"));

        return Base64.getEncoder().encodeToString(encryptedBytes);
    }
	
	
	public static String decryptMessage(String encryptedMessage, SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);

        byte[] encryptedBytes = Base64.getDecoder().decode(encryptedMessage);
        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);

        return new String(decryptedBytes, "UTF-8");
    }
}
