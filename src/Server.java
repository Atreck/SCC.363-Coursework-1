import java.nio.charset.Charset;
import java.nio.file.Path;
import java.rmi.Naming;
import java.security.*;
import java.util.HashMap;
import java.util.Random;

import org.apache.commons.codec.binary.*;
import de.taimos.totp.*;
import signatures.SignatureUtil;

import com.google.zxing.qrcode.*;
import com.google.zxing.*;
import com.google.zxing.common.*;
import com.google.zxing.client.j2se.*;

import java.nio.file.*;
public class Server extends java.rmi.server.UnicastRemoteObject implements MedicalService
{
    //TODO: Add docs and comments.

    private static HashMap<String, User> database = new HashMap<>();
    private String tempUsername;
    private final int CHALLENGE_LEN = 50;
    private final int PASS_INCORRECT = 2;
    private final int PASS_CORRECT = 3;
    private final int CODE_INCORRECT = 4;
    private final int CODE_CORRECT = 5;
    private final int SIGN_CORRECT = 6;
    private final int SIGN_INCORRECT = 7;
    private final int LOCKED = 8;

    public Server() throws Exception
    {
        super();
        addUser("admin", "password", "BGLBEVX44CZC45IOAQI3IFJBDBEOYY3A");
        addUser("testUser", "MyPassword#3456", "MAAULT5OH5P4ZAW7JC5PWJIMZZ7VWRNU");
    }

    public Message authenticateUser(Message data) throws Exception
    {
        // Extract data from the message
        Main client = data.getClient();
        String username = data.getUsername();
        System.out.println("** Authenticating user: " + username);

        // Challenge the user
        byte[] array = new byte[CHALLENGE_LEN];
        new Random().nextBytes(array);
        String challenge = new String(array, Charset.forName("UTF-8"));
        String signedChallenge = client.signChallenge(challenge);
        PublicKey pubKey = SignatureUtil.retrieveKeys(username, SignatureUtil.ALGO_NAME).getPublic();
        boolean signCorrect = SignatureUtil.verifyChallenge(signedChallenge, challenge, pubKey);
        if (signCorrect) {
            System.out.println("** Authentication successful for user: " + username);
            return new Message(SIGN_CORRECT);
        }
        else {
            System.out.println("This is not user " + username + "! Impostor detected.");
            return new Message(SIGN_INCORRECT);
        }
    }

    public Message verifyPassword(Message message) throws  Exception {
        String username = message.getUsername();
        String pass = message.getPassword();

        User user = database.get(username);

        if (!pass.equals(user.getPassword()) && user.getTries() > 0)
        {
            user.setTries(user.getTries()-1);

            if(user.getTries() == 0)
            {
                //Add implementation in Server.java to lock out user using the lockUser() method.
                System.out.println("This account has been locked. Please contact the system administrator to unlock your account.");
                lockUser(username);
                return new Message(LOCKED);
            }
            return new Message(PASS_INCORRECT, user.getTries());
        }
        // reset the tries
        user.setTries(3);
        return new Message(PASS_CORRECT);
    }

    public Message verifyCode(Message message) throws Exception {
        String username = message.getUsername();
        String code = message.getPassword();  // password field can be used to carry code as well

        User user = database.get(username);

        if(user.getSecretCode() != null) {
            if(!code.equals(TOTPcode(user.getSecretCode())) && user.getTries() > 0) {
                user.setTries(user.getTries()-1);

                if(user.getTries() == 0)
                {
                    //Add implementation in Server.java to lock out user using the lockUser() method.
                    System.out.println("This account has been locked. Please contact the system administrator to unlock your account.");
                    lockUser(username);
                    return new Message(LOCKED);
                }
                return new Message(CODE_INCORRECT, user.getTries());
            }
        }
        // reset the tries
        user.setTries(3);
        return new Message(CODE_CORRECT, user);
    }

    public void addUser(String username, String password, String key) throws Exception
    {
        register(username, password);
        database.put(username, new User(username, password, key));
    }

    public void addUser(Message message) throws Exception {
        String username = message.getUsername();
        String password = message.getPassword();
        String key = message.getCode();

        database.put(username, new User(username, password, key));
        register(username, password);
    }

    public boolean userExists(String user) throws Exception
    {
        return database.containsKey(user);
    }

    public Message validateUsername(Message request) throws Exception {
        tempUsername = null;
        tempUsername = request.getUsername();
        boolean valid = !userExists(tempUsername);
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

    public String secretKeyGen() throws Exception
	{
		byte[] bytes = new byte[20];
        new SecureRandom().nextBytes(bytes);
    	return new Base32().encodeToString(bytes);
	}

	public String TOTPcode(String secretKey) throws Exception
	{
    	byte[] bytes = new Base32().decode(secretKey);
		String hexKey = Hex.encodeHexString(bytes);
		return TOTP.getOTP(hexKey);
    }

    public void createQRimage(Message m) throws Exception
    {
        String content = "otpauth://totp/MedicalPortal: " + m.getUsername() + "?secret=" + m.getCode() + "&algorithm=SHA1&digits=6&period=30";
        BitMatrix matrix = new QRCodeWriter().encode(content, BarcodeFormat.QR_CODE, 200, 200);
        Path path = FileSystems.getDefault().getPath("./" + m.getUsername() + "_QRcode.png");
        MatrixToImageWriter.writeToPath(matrix, "PNG", path);
    }

    public void lockUser(String user) throws Exception
    {
        // Okay this is just so beautiful, can we leave it like that please hahahah ~ Kas
        System.out.println("SKIDADDLE SKIDOODLE THE USER " + user + " IS NOW A NOODLE");
    }
    public static void main(String[] args) throws Exception
    {
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
