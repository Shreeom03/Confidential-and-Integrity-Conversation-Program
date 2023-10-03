package SecuredConversationBetweenClientAndServer;

import java.net.*;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;
import javax.crypto.*;
import java.io.*;

public class Server {
	public static void main(String args[]) throws Exception {
		SecretKeyGenerator secretkey = new SecretKeyGenerator();
		
		final int port = 12345;

        try (ServerSocket serverSocket = new ServerSocket(port)) {
            System.out.println("Server is listening on port " + port);

            Socket clientSocket = serverSocket.accept();
            System.out.println("Connection established with " + clientSocket.getInetAddress());

            BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
            PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true);
            
            java.security.PublicKey publickey = convertStringToPublicKey(in.readLine());
            
            String s  = encryptAESKeyWithRSAPublicKey(secretkey.secretkey , publickey);
            out.println(s);
       
            
            
            Scanner sc = new Scanner(System.in);

            String message;
            while (!(message = in.readLine()).equalsIgnoreCase("EXIT")) {
                int hcode = Integer.parseInt(in.readLine());
                
                if(message.hashCode() != hcode) {
                	System.out.println("Invalid Message");
                	return;
                }
                
                message = decryptMessage(message,secretkey.secretkey);
                if(message.equals("EXIT")) {
                	System.out.println("BYE");
                	break;
                }
                
                System.out.println(message);
                System.out.println("Your message : ");

                String response = "Server response: " + sc.nextLine();
                String hash = Integer.toString(response.hashCode());
                out.println(encryptMessage(response , secretkey.secretkey));
                out.println(hash);
            }
            
            sc.close();
            in.close();
            out.close();
            clientSocket.close();
            serverSocket.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
		
	}
	
	public static String encryptAESKeyWithRSAPublicKey(SecretKey aesSecretKey, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedAESKeyBytes = cipher.doFinal(aesSecretKey.getEncoded());
        return Base64.getEncoder().encodeToString(encryptedAESKeyBytes);
    }
	
	public static PublicKey convertStringToPublicKey(String publicKeyString) throws Exception {

        byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyString);

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
        PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

        return publicKey;
    }
	
	public static String encryptMessage(String message, SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);

        byte[] encryptedBytes = cipher.doFinal(message.getBytes("UTF-8"));

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
