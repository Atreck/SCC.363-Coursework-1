package main;

import java.nio.charset.Charset;
import java.nio.file.Path;
import java.rmi.Naming;
import java.security.*;
import java.util.HashMap;
import java.util.Random;

import com.google.zxing.qrcode.QRCodeWriter;
import encryption.CryptUtil;
import org.apache.commons.codec.binary.*;
import de.taimos.totp.*;
import signatures.SignUtil;

import com.google.zxing.*;
import com.google.zxing.common.*;
import com.google.zxing.client.j2se.*;

import javax.crypto.SealedObject;
import javax.crypto.SecretKey;
import java.nio.file.*;
public class Server extends java.rmi.server.UnicastRemoteObject implements MedicalService {

    //TODO: Add docs and comments.

    private static HashMap<String, User> database = new HashMap<>();
    private String tempUsername;
    public static final int CHALLENGE_LEN = 50;
    private final int PASS_OK = 1;
    private final int CREDENTIALS_OK = 2;
    private final int CREDENTIALS_BAD = 3;
    private final int CODE_INCORRECT = 4;
    private final int CODE_CORRECT = 5;
    private final int LOCKED = 8;

    public Server() throws Exception {
        super();
        addUser(new Message("admin", "password", "BGLBEVX44CZC45IOAQI3IFJBDBEOYY3A"));
        addUser(new Message("testUser", "MyPassword#3456", "MAAULT5OH5P4ZAW7JC5PWJIMZZ7VWRNU"));
    }

    public SafeMessage authenticateUser(SafeMessage safeMessage) throws Exception {
        PrivateKey serverPrivateKey = CryptUtil.getPrivateKey(CryptUtil.ALGO_NAME, "server");
        SecretKey secretKey = CryptUtil.decrypt(safeMessage.getSecretKeyEncrypted(), serverPrivateKey);
        Message data = CryptUtil.decrypt(safeMessage.getObj(), secretKey);
        // Extract data from the message
        Frontend client = data.getClient();
        String username = data.getUsername();
        String pass = data.getPassword();

        System.out.println("** Authenticating user: " + username);
        boolean signCorrect = challengeUser(client, username);
        if (!signCorrect) {
            Message msg = new Message(CREDENTIALS_BAD);
            return prepResponse(msg, username);
        }

        boolean username_valid = this.validateUsername(username);
        int pass_valid = this.verifyPassword(username, pass);
        if (username_valid && pass_valid == PASS_OK) {
            Message msg = new Message(CREDENTIALS_OK);
            return prepResponse(msg, username);
        } else if (pass_valid == LOCKED) {
            Message msg = new Message(LOCKED);
            return prepResponse(msg, username);
        }
        else {
            Message msg = new Message(CREDENTIALS_BAD);
            return prepResponse(msg, username);
        }
    }

    public SafeMessage prepResponse(Message msg, String username) throws Exception {
        PublicKey userPublicKey = CryptUtil.getPublicKey(CryptUtil.ALGO_NAME, username);
        SecretKey newKey = CryptUtil.genSecretKey();
        SealedObject response = CryptUtil.encrypt(msg, newKey);
        byte[] encryptedKey = CryptUtil.encrypt(newKey, userPublicKey);

        return new SafeMessage(response, encryptedKey);
    }

    public boolean challengeUser(Frontend client, String username) throws Exception {
        // Challenge the user
        System.out.println("** Challenging user: " + username);
        byte[] array = new byte[CHALLENGE_LEN];
        new Random().nextBytes(array);
        String challenge = new String(array, Charset.forName("UTF-8"));
        String signedChallenge = client.signChallenge(challenge);
        PublicKey pubKey = CryptUtil.getPublicKey(CryptUtil.ALGO_NAME, username);
        boolean signCorrect = SignUtil.verifyChallenge(signedChallenge, challenge, pubKey);
        System.out.println("** Challenge correctly signed: " + signCorrect);

        return signCorrect;
    }

    public String signChallenge(String challenge) throws Exception {
        System.out.println("** Signing challenge sent by a user");
        PrivateKey privKey = CryptUtil.getPrivateKey(CryptUtil.ALGO_NAME, "server");
        String signed = SignUtil.signChallenge(challenge, privKey);
        return signed;
    }

    public int verifyPassword(String username, String pass) throws  Exception {
        User user = database.get(username);
        System.out.println("** Verifying password for user: " + username);

        if (!pass.equals(user.getPassword()) && user.getTries() > 0) {
            user.setTries(user.getTries()-1);

            if(user.getTries() == 0) {
                //Add implementation in Server.java to lock out user using the lockUser() method.
                System.out.println("** Password incorrect - account locked for user: " + username);
                lockUser(username);
                return LOCKED;
            }
            System.out.println("** Password incorrect for user: " + username);
            return CREDENTIALS_BAD;
        }
        // reset the tries
        user.setTries(3);
        System.out.println("** Password correct for user: " + username);
        return PASS_OK;
    }

    public SafeMessage verifyCode(SafeMessage safeMessage) throws Exception {
        PrivateKey serverPrivateKey = CryptUtil.getPrivateKey(CryptUtil.ALGO_NAME, "server");
        SecretKey secretKey = CryptUtil.decrypt(safeMessage.getSecretKeyEncrypted(), serverPrivateKey);
        Message message = CryptUtil.decrypt(safeMessage.getObj(), secretKey);
        String username = message.getUsername();
        String code = message.getPassword();  // password field can be used to carry code as well

        User user = database.get(username);
        System.out.println("** Verifying code for user: " + username);

        if(user.getSecretCode() != null) {
            if(!code.equals(TOTPcode(user.getSecretCode())) && user.getTries() > 0) {
                user.setTries(user.getTries()-1);

                if(user.getTries() == 0) {
                    //Add implementation in Server.java to lock out user using the lockUser() method
                    lockUser(username);
                    System.out.println("** Incorrect code - account has been locked for user: " + username);
                    Message msg = new Message(LOCKED);
                    return prepResponse(msg, username);
                }
                System.out.println("** Incorrect code for user: " + username);
                Message msg = new Message(CODE_INCORRECT, user.getTries());
                return prepResponse(msg, username);
            }
        }
        // reset the tries
        user.setTries(3);
        System.out.println("** Verification code correct for user: " + username);
        Message msg = new Message(CODE_CORRECT, user);
        return prepResponse(msg, username);
    }

    public void addUser(Message message) throws Exception {
        String username = message.getUsername();
        String password = message.getPassword();
        String key = message.getCode();

        database.put(username, new User(username, password, key));
        register(username, password);
    }

    public boolean validateUsername(String username) throws Exception {
        tempUsername = username;
        boolean valid = database.containsKey(tempUsername);
        System.out.println("** Validating username for : " + tempUsername);
        System.out.println("** Username valid: " + valid);
        return valid;
    }

    public Message validateUsername(Message msg) throws Exception {
        tempUsername = msg.getUsername();
        boolean valid = !database.containsKey(tempUsername);
        System.out.println("Validating username for " + tempUsername + ": " + valid);
        return new Message(valid);
    }

    public Message validatePassword(Message message) throws Exception {
        String password = message.getPassword();
        boolean valid = strengthCheck(password);
        if (valid) {
            // ready to be stored
            String saltedPass = saltPass(password);
        }
        else { System.out.println("Registration failed with username:" + tempUsername +
                "and password: " + password);}
        return new Message(valid);
    }

    public String secretKeyGen() throws Exception {
		byte[] bytes = new byte[20];
        new SecureRandom().nextBytes(bytes);
    	return new Base32().encodeToString(bytes);
	}

	public String TOTPcode(String secretKey) throws Exception {
    	byte[] bytes = new Base32().decode(secretKey);
		String hexKey = Hex.encodeHexString(bytes);
		return TOTP.getOTP(hexKey);
    }

    public void createQRimage(Message m) throws Exception {
        String content = "otpauth://totp/MedicalPortal: " + m.getUsername() + "?secret=" + m.getCode() + "&algorithm=SHA1&digits=6&period=30";
        BitMatrix matrix = new QRCodeWriter().encode(content, BarcodeFormat.QR_CODE, 200, 200);
        Path path = FileSystems.getDefault().getPath("./" + m.getUsername() + "_QRcode.png");
        MatrixToImageWriter.writeToPath(matrix, "PNG", path);
    }

    public void lockUser(String user) throws Exception {
        // Okay this is just so beautiful, can we leave it like that please hahahah ~ Kas
        System.out.println("SKIDADDLE SKIDOODLE THE USER " + user + " IS NOW A NOODLE");
    }
    public static void main(String[] args) throws Exception {
        try {
            System.out.println("Starting the server...");
            MedicalService server = new Server();
            Naming.rebind("rmi://localhost/MedicalService", server);
            System.out.println("Server running at rmi://localhost/MedicalService");
        } catch(Exception e) {
            System.out.println("Server error: " + e);
        }
    }
}
