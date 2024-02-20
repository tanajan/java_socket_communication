import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import java.io.*;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.*;

import static java.time.format.DateTimeFormatter.RFC_1123_DATE_TIME;

class client {

	private static List<String> users = new ArrayList<>();
	public static void main(String [] args) throws Exception {

		//Users in the system
		File directoryPath = new File("./");
		File filelist[] =directoryPath.listFiles();
		String fname;
		int index;
		for(File file : filelist) {
			if(file.getName().contains(".prv")) {
				fname = file.getName();
				index = fname.indexOf(".prv");
				fname = fname.substring(0,index);
				users.add(fname.toLowerCase());
			}
		}

		String host = args[0]; // hostname of server
		int port = Integer.parseInt(args[1]); // port of server
		String secretString = "abeedaboo:";
		
		//Server connection
		Socket s = new Socket(host, port);
		ObjectOutputStream dos = new ObjectOutputStream(s.getOutputStream());
		ObjectInputStream dis = new ObjectInputStream(s.getInputStream());
        //Say hi
		dos.writeObject(hashUserId(secretString,args[2]));

		//Incoming Msg
		Object numofmsg = dis.readObject();
		if((int) numofmsg == 0) {
			System.out.println("You have 0 incoming message.");
		} else {
			System.out.println("You have "+ numofmsg + " incoming message.");
			System.out.println("===============================");
			for(int i = 0; i < (int) numofmsg ;i++ ) {
				Object incoming = dis.readObject();
				if(!verifySignature((Message) incoming)) {
					System.out.println("Client: Signature verification failed. Terminate the system.");
					System.exit(1);
				}
				System.out.println("Date : "+((Message) incoming).getTimestamp());
				System.out.println("Message : " + decryptClientMessage(((Message) incoming).getEncryptedContent(),args[2]));
				System.out.println("===============================");
			}
		}
        
		System.out.println("Do you want to send a message? [y/n]");
		Scanner sc = new Scanner(System.in);
		String choice = sc.nextLine();

		switch(choice.toUpperCase()) {

			case "Y":
				System.out.println("Enter userid of recipient:");
				String recipientID = sc.nextLine();
				if(!checkuserExist(recipientID)) {
					System.out.println(recipientID + " is not in the system.");
					System.out.println("Terminating the system!");
					System.exit(1);
				}
				System.out.println("Type your message:");
				String messageContent = sc.nextLine();

				// Encrypt the message here
				String encryptedMsg = encryptedMsg(recipientID + ":" + messageContent,recipientID);

				// Generate the signature for the message
				byte[] signatureBytes = genSignature(encryptedMsg, args[2]).getBytes(); // Ensure generateSignature returns byte[] directly

				// Sender's user ID from command line arguments

				String senderUserId = args[2]; // Assuming sender's userId is passed as a command line argument
				// Create and send the Message object to the server
				Message messageToSend = new Message(encryptedMsg, getCurrentTimeStamp(), signatureBytes,recipientID,senderUserId);
				dos.writeObject(messageToSend);
				System.out.println("Message Sent to " + recipientID);
				System.out.println();
				s.close();
				System.exit(1);
				break;
			case "N":

				System.out.print("Thank you for using our system !");
				System.out.println();

			break;
		default:
			System.out.println("Invalid input ! Terminating . . . .");
			System.out.println();
			s.close();
			System.exit(1);
		}
		String aLine = null;

		while ((aLine = sc.nextLine()) != null) {

//			System.out.println(dis.readUTF());

		}
	}
	public static String hashUserId(String secretString, String userID) {
		String user = secretString + userID;
		try {
			MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] messageDigest = md.digest(user.getBytes());
            StringBuilder hexString = new StringBuilder();
            for (byte b : messageDigest) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) {
                    hexString.append('0');
                }
                hexString.append(hex);
            }

            return hexString.toString();
		} catch(NoSuchAlgorithmException e) {
			e.printStackTrace();
			return null;
		}
	}
	
	private static String encryptedMsg(String msg,String recipientID) throws Exception {
		String filename =  "Server.pub";
		PublicKey serverpubkey = loadPublicKey(filename);
		//RSA Cipher Instance
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.ENCRYPT_MODE, serverpubkey);

		//Encrypting process
		byte[] encryptedBytes = cipher.doFinal(msg.getBytes());
		return Base64.getEncoder().encodeToString(encryptedBytes);
	}
	
	private static PublicKey loadPublicKey(String filename) throws Exception {
        try (FileInputStream fis = new FileInputStream(filename)) {
            byte[] encodedKey = fis.readAllBytes(); 
            X509EncodedKeySpec spec = new X509EncodedKeySpec(encodedKey);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return keyFactory.generatePublic(spec);
        } catch (FileNotFoundException e) {
            System.err.println("Public key file not found: " + filename);
            throw e;
        } 
    }

    private static PrivateKey loadPrivateKey(String filename) throws Exception {
        try (FileInputStream fis = new FileInputStream(filename)) {
            byte[] encodedKey = fis.readAllBytes();
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(encodedKey);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return keyFactory.generatePrivate(spec);
        }
    }
    
    private static String genSignature(String data,String senderId) throws Exception {
    	String filename = senderId +".prv";
    	PrivateKey sendkey = loadPrivateKey(filename);
    	//Create Signature instance using SHA256withRSA
    	Signature sendersignature = Signature.getInstance("SHA256withRSA");
    	sendersignature.initSign(sendkey);
    	
    	//Generate timestamp and update to signature
    	String timestamp = getCurrentTimeStamp();
    	String datawithtimestamp = data + timestamp;
    	sendersignature.update(datawithtimestamp.getBytes());
    	
    	//Generate Signature
    	byte[] signatureByte = sendersignature.sign();
    	
    	return Base64.getEncoder().encodeToString(signatureByte);
    }

    private static String getCurrentTimeStamp() {
    	Instant instant = Instant.now();
    	DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss'Z'").withZone(ZoneId.systemDefault());
		DateTimeFormatter rfc1123Formatter = DateTimeFormatter
				.ofPattern("EEE, dd MMM yyyy HH:mm:ss 'GMT'", Locale.ENGLISH)
				.withZone(ZoneId.of("GMT"));
		return rfc1123Formatter.format(instant);
    }

	private static boolean verifySignature(Message m) throws Exception {
		String filename = m.getSenderUserId() +".pub";
		PublicKey sendkey = loadPublicKey(filename);

		// Create Signature instance using SHA256withRSA algorithm
		Signature verifier = Signature.getInstance("SHA256withRSA");
		verifier.initVerify(sendkey);
		verifier.update((m.getEncryptedContent()+m.getTimestamp()).getBytes());

		// Verify the signature
		return verifier.verify(Base64.getDecoder().decode(m.getSignature()));
	}
	private static String decryptClientMessage(String encryptedMessage,String userid) throws Exception {
		try {
			String decrypted = "";

			// Simulated private key of the server
			PrivateKey recipientpubkey = loadPrivateKey(userid + ".prv");

			// Create RSA cipher instance
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.DECRYPT_MODE, recipientpubkey);

			// Decrypt the Base64 encoded message
			byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedMessage));

			// Convert the decrypted bytes to a string
			decrypted = new String(decryptedBytes, StandardCharsets.UTF_8);

			return decrypted;

		} catch (BadPaddingException e) {
			e.printStackTrace();
			return "Badpadding";
		}
	}
	private static boolean checkuserExist(String user) {
		for (String s : users) {
			if(s.equals(user)) {
				return true;
			}
		}
		return false;
	}

}

