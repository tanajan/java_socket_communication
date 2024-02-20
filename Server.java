import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

class Server2 {
    private static String  secretString = "abeedaboo:";
    private static List<Message> messages = new ArrayList<>();
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
                users.add(fname);
            }
        }

        int port = Integer.parseInt(args[0]);
        ServerSocket ss = new ServerSocket(port);
        System.out.println("Server running on port " + port);
        System.out.println("Waiting incoming connection...");
        List<Message> usermsg = new ArrayList<>();
        while(true) {
            Socket s = ss.accept();
            ObjectOutputStream dos = new ObjectOutputStream(s.getOutputStream());
            ObjectInputStream dis = new ObjectInputStream(s.getInputStream());

            try {
                while (true) {

                        String hashuser = String.valueOf(dis.readObject());
                        System.out.println(hashuser + " logged in");

                        //Send user received msg
                        usermsg = getMessagetoUser(hashuser);
                        if(usermsg.isEmpty()) {
                            dos.writeObject(0);
                        } else {
//                            dos.writeObject(Integer.toString(usermsg.size()));
                            dos.writeObject(usermsg.size());
                            for (Message msg : usermsg) {
                                byte[] sig = genSignature(msg.getEncryptedContent(),msg.getTimestamp()).getBytes();
                                Message touser = new Message(msg.getEncryptedContent(),msg.getTimestamp(),sig,msg.getRecipientUserId(),"server");
                                dos.writeObject(touser);
                            }
                        }

                        //Receiving message from user (if any)
                    try {
                        Message clientmsg = (Message) dis.readObject();
                        processUserMsg(clientmsg);
                    } catch (ClassNotFoundException e) {
                        e.printStackTrace();
                    }

                }
            }
            catch(IOException e) {
                System.err.println("Client closed its connection.");
            } catch(BadPaddingException e) {
                System.out.println("Bad Padding! Discard the message !");

            }
        }
    }

    private static List<Message> getMessagetoUser(String HashuserId) {
        Message temp;
        List<Message> tome = new ArrayList<>();
        for (Message msg : messages) {
            if(hashUserId(secretString,msg.getRecipientUserId()).equals(HashuserId)) {
                tome.add(msg);
            }
        }
        return tome;
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

    private static boolean verifyClientSignature(Message m) throws Exception {
        String filename = m.getSenderUserId() +".pub";
        PublicKey sendkey = loadPublicKey(filename);

        // Create Signature instance using SHA256withRSA algorithm
        Signature verifier = Signature.getInstance("SHA256withRSA");
        verifier.initVerify(sendkey);
        verifier.update((m.getEncryptedContent()+m.getTimestamp()).getBytes());

        // Verify the signature
        return verifier.verify(Base64.getDecoder().decode(m.getSignature()));
    }
    private static PrivateKey loadPrivateKey(String filename) throws Exception {
        try (FileInputStream fis = new FileInputStream(filename)) {
            byte[] encodedKey = fis.readAllBytes();
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(encodedKey);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return keyFactory.generatePrivate(spec);
        }
    }

    private static void processUserMsg(Message clientmessage) throws Exception {
        if(!verifyClientSignature(clientmessage)) {
            System.out.println("Server: Signature verification failed. Discarding message.");
            return;
        }
        String encrypted = decryptClientMessage(clientmessage.getEncryptedContent());
        String[] encryptedSpilt = encrypted.split(":");
        String recipientID = encryptedSpilt[0];
        String message = encryptedSpilt[1];
        String encryptedmsg = encryptedMsg(message,recipientID);
        Message temp = new Message(encryptedmsg,clientmessage.getTimestamp(),"".getBytes(),recipientID,"server");
        System.out.println("message received from sender " + clientmessage.getSenderUserId());
        System.out.println("recipient id : " + recipientID);
        System.out.println("message : " + message);
        messages.add(temp);
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
        } catch (IOException e) {
            System.out.println("Error reading public key file" + e.getMessage());
            throw e;
        }
    }

    private static String decryptClientMessage(String encryptedMessage) throws Exception {
        try {
            String decrypted = "";

                // Simulated private key of the server
                PrivateKey recipientpubkey = loadPrivateKey("server.prv");

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

    private static String encryptedMsg(String msg,String recipientID) throws Exception {
        String filename =  recipientID + ".pub";
        PublicKey recipub = loadPublicKey(filename);
        //RSA Cipher Instance
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, recipub);

        //Encrypting process
        byte[] encryptedBytes = cipher.doFinal(msg.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    private static String genSignature(String data, String timestamp) throws Exception {
        String filename = "Server.prv";
        PrivateKey sendkey = loadPrivateKey(filename);
        //Create Signature instance using SHA256withRSA
        Signature sendersignature = Signature.getInstance("SHA256withRSA");
        sendersignature.initSign(sendkey);

        //Generate timestamp and update to signature
        String datawithtimestamp = data + timestamp;
        sendersignature.update(datawithtimestamp.getBytes());

        //Generate Signature
        byte[] signatureByte = sendersignature.sign();

        return Base64.getEncoder().encodeToString(signatureByte);
    }

    private static String getCurrentTimeStamp() {
        Instant instant = Instant.now();

        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss'Z'").withZone(ZoneId.systemDefault());
        return formatter.format(instant);
    }

}