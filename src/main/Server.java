package main;

import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.file.Path;
import java.rmi.Naming;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Random;

import com.google.zxing.qrcode.QRCodeWriter;
import encryption.CryptUtil;
import org.apache.commons.codec.binary.*;
import de.taimos.totp.*;
import org.json.simple.parser.ParseException;
import signatures.SignUtil;

import com.google.zxing.*;
import com.google.zxing.common.*;
import com.google.zxing.client.j2se.*;

import javax.crypto.*;
import java.nio.file.*;
public class Server extends java.rmi.server.UnicastRemoteObject implements MedicalService {

    //TODO: Add docs and comments.

    // serving as a cache for active users (user, their permissions)
    /* We could even add a separate thread when the server is starting to loop through active users and check
    ** (by storing timestamps for example?) when the last time they performed any kind of action was - if
    ** current timestamp - last_accessed >= timeout ----> log out a user
     */
//    private static HashMap<String, HashSet<Long>> activeUsers = new HashMap<>();
    public static final int CHALLENGE_LEN = 50;
    private static final int PASS_OK = 1;
    private final int CREDENTIALS_OK = 2;
    private final int CREDENTIALS_BAD = 3;
    private final int CODE_INCORRECT = 4;
    private final int CODE_CORRECT = 5;
    private final int LOCKED = 8;
    private final int REGISTRATION_SUCCESS = 9;
    private final int REGISTRATION_FAIL = 10;

    private final int OK = 200;
    private final int FORBIDDEN = 403;
//    private final int NOT_ALLOWED = 405;
    private final int ERROR = 400;

    public Server() throws Exception {
        super();
//        addAdmin("admin", "Joe", "Admindoe", "superUser89@pass", "BGLBEVX44CZC45IOAQI3IFJBDBEOYY3A");
//        addPatient(new Message("Joe", "Doe", "testUser", "MyPassword#3456", "jdoe@email.com","MAAULT5OH5P4ZAW7JC5PWJIMZZ7VWRNU"));
    }

    public SafeMessage authenticateUser(SafeMessage safeMessage) throws Exception {
        PrivateKey serverPrivateKey = CryptUtil.getPrivateKey(CryptUtil.ALGO_NAME, "server");
        SecretKey secretKey = CryptUtil.decrypt(safeMessage.getSecretKeyEncrypted(), serverPrivateKey);
        Message data = CryptUtil.decrypt(safeMessage.getObj(), secretKey);
        // Extract data from the message
        Main client = data.getClient();
        String username = data.getUsername();
        String pass = data.getPassword();

        System.out.println("** Authenticating user: " + username);
        boolean signCorrect = challengeUser(client, username);
        if (!signCorrect) {
            Message msg = new Message(CREDENTIALS_BAD);
            return prepResponse(msg, username);
        }

        System.out.println("** Validating username for : " + username);
        boolean username_valid = RecordsUtil.userExists(username);
        System.out.println("** Username valid: " + username_valid);
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

    public boolean challengeUser(Main client, String username) throws Exception {
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
        System.out.println("** Verifying password for user: " + username);
        int status = RecordsUtil.passMatches(username, pass);

        if(status == LOCKED) {
            //Add implementation in Server.java to lock out user using the lockUser() method.
            System.out.println("** Password incorrect - account locked for user: " + username);
            lockUser(username);
            return LOCKED;
        }
        else if (status == CREDENTIALS_BAD) {
            System.out.println("** Password incorrect for user: " + username);
            return CREDENTIALS_BAD;
        }
        // else pass is ok
        System.out.println("** Password correct for user: " + username);
        return PASS_OK;
    }

    public SafeMessage verifyCode(SafeMessage safeMessage) throws Exception {
        PrivateKey serverPrivateKey = CryptUtil.getPrivateKey(CryptUtil.ALGO_NAME, "server");
        SecretKey secretKey = CryptUtil.decrypt(safeMessage.getSecretKeyEncrypted(), serverPrivateKey);
        Message message = CryptUtil.decrypt(safeMessage.getObj(), secretKey);
        String username = message.getUsername();
        String code = message.getPassword();  // password field can be used to carry code as well


        System.out.println("** Verifying code for user: " + username);
        int status = RecordsUtil.codeMatches(username, code);

        if (status == LOCKED) {
            //Add implementation in Server.java to lock out user using the lockUser() method
            lockUser(username);
            System.out.println("** Incorrect code - account has been locked for user: " + username);
            Message msg = new Message(LOCKED);
            return prepResponse(msg, username);
        }
        else if (status == CODE_INCORRECT) {
            System.out.println("** Incorrect code for user: " + username);
            Message msg = new Message(CODE_INCORRECT);
            return prepResponse(msg, username);
        }
        System.out.println("** Verification code correct for user: " + username);
        Context context = RecordsUtil.getContext(username);
//        activeUsers.put(username, context.getPermissions());
        System.out.println();
        Message msg = new Message(CODE_CORRECT, context.getGroup());

        return prepResponse(msg, username);
    }

    public int addPatient(Message message) throws Exception {
        String username = message.getUsername();
        String password = message.getPassword();
        String name = message.getName();
        String email = message.getEmail();
        String surname = message.getSurname();
        String code = message.getCode();

        if (!code.equals("none")) {
            createQRimage(username, code);
        }

        boolean passStrong = strengthCheck(password);
        if (!passStrong) { return REGISTRATION_FAIL;}

        boolean userExists = RecordsUtil.userExists(username);
        if (!userExists) {
            RecordsUtil.addPatient(username, name, surname, email, password, code);
            register(username);
            return REGISTRATION_SUCCESS;
        }
        return REGISTRATION_FAIL;
    }

    public void addAdmin(String username, String name, String surname, String password, String code) throws Exception {
        // first letter of a name + surname + @mediservice.com to create staff emails
        String email = name.substring(0, 1) + surname + "@mediservice.com";

//      Commented out as there was a qr image already created for this one
//        String key = secretKeyGen();
//      createQRimage(username, code);
        boolean passStrong = strengthCheck(password);
        if (!passStrong) {
            System.out.println("** Admin registration failed - pass too weak");
            return;
        }

        boolean userExists = RecordsUtil.userExists(username);
        if (!userExists) {
            RecordsUtil.addAdmin(username, name, surname, email, password, code);
            register(username);
            System.out.println("** Admin registration successful with username: " + username);
            return;
        }
        System.out.println("** Admin registration failed, account with such username may already exist.");

    }

    public String secretKeyGen() throws Exception {
		byte[] bytes = new byte[20];
        new SecureRandom().nextBytes(bytes);
    	return new Base32().encodeToString(bytes);
	}

    public void createQRimage(String username, String code) throws Exception {
        String content = "otpauth://totp/MedicalPortal: " + username + "?secret=" + code + "&algorithm=SHA1&digits=6&period=30";
        BitMatrix matrix = new QRCodeWriter().encode(content, BarcodeFormat.QR_CODE, 200, 200);
        Path path = FileSystems.getDefault().getPath("./" + username + "_QRcode.png");
        MatrixToImageWriter.writeToPath(matrix, "PNG", path);
    }

    public void logout(SafeMessage safeMessage) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException, ClassNotFoundException,
            InvalidKeyException, BadPaddingException, IllegalBlockSizeException, NoSuchPaddingException {
        PrivateKey serverPrivateKey = CryptUtil.getPrivateKey(CryptUtil.ALGO_NAME, "server");
        SecretKey secretKey = CryptUtil.decrypt(safeMessage.getSecretKeyEncrypted(), serverPrivateKey);
        Message data = CryptUtil.decrypt(safeMessage.getObj(), secretKey);
        String username = data.getUsername();

    }

    public SafeMessage getRecords(SafeMessage safeMessage) throws
            Exception {

        PrivateKey serverPrivateKey = CryptUtil.getPrivateKey(CryptUtil.ALGO_NAME, "server");
        SecretKey secretKey = CryptUtil.decrypt(safeMessage.getSecretKeyEncrypted(), serverPrivateKey);
        Message data = CryptUtil.decrypt(safeMessage.getObj(), secretKey);
        // Extract data from the message
        String issuer = data.getUsername();
        String usertosee = data.getPassword();        // password field can be used to carry this this info


        String records = "";
        Message message = new Message(FORBIDDEN, records);
        boolean status = false;
        // we check if it is a Patient just accessing their own data or is it someone else
        String group = RecordsUtil.getContext(issuer).getGroup();
        if (!issuer.equals(usertosee)) {
            status = RecordsUtil.hasReadPatientsPermission(issuer);
            if (status) {
                records = RecordsUtil.readPatient(usertosee);
                message = new Message(OK, records);
            }
        } else if (group.equals("Patients")) {         // issuer is the same as the user to see and belongs to Patients
            records = RecordsUtil.readPatient(usertosee);
            message = new Message(OK, records);
        }

        return prepResponse(message, issuer);
    }

    public SafeMessage updateRecords(SafeMessage safeMessage)
            throws Exception {

        PrivateKey serverPrivateKey = CryptUtil.getPrivateKey(CryptUtil.ALGO_NAME, "server");
        SecretKey secretKey = CryptUtil.decrypt(safeMessage.getSecretKeyEncrypted(), serverPrivateKey);
        Message data = CryptUtil.decrypt(safeMessage.getObj(), secretKey);
        // Extract data from the message
        String issuer = data.getUsername();
        String usertosee = data.getPassword();        // password field can be used to carry this this info

        /* I will not include the actual update information, so it is kind of just a simulation
           instead I will just send a response (OK - updated, FORBIDDEN - not updated, lack of permissions)
         */
        Message message = new Message(FORBIDDEN);
        boolean status = false;
        // we check if it is a Patient just accessing their own data or is it someone else
        String group = RecordsUtil.getContext(issuer).getGroup();
        if (!issuer.equals(usertosee)) {
            System.out.println("Update user");
//            status = RecordsUtil.hasUpdatePatientsPermission(issuer);
            if (status) {
                // here we update records and send back an OK message
                message = new Message(OK);
            }
        } else if (group.equals("Patients")) {         // issuer is the same as the user to see and belongs to Patients
            // here we update records and send back an OK message
            message = new Message(OK);
        }

        return prepResponse(message, issuer);
    }


    // TODO: I added a "locked" field in users files so can be just updated there and users denied access based on its value
    // 0 - not locked, 1 - locked
    public void lockUser(String user) throws Exception {
        // Okay this is just so beautiful, can we leave it like that please hahahah ~ Kas
        System.out.println("SKIDADDLE SKIDOODLE THE USER " + user + " IS NOW A NOODLE");
        // Needs implementation
//        RecordsUtil.blockUser(user);
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
