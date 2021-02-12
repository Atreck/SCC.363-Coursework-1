package main;

import java.io.File;
import java.io.IOException;
import java.nio.charset.Charset;
import java.rmi.Naming;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.*;
import java.util.logging.FileHandler;
import java.util.logging.Handler;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;
import java.text.SimpleDateFormat;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.crypto.SealedObject;
import javax.crypto.SecretKey;

import org.apache.commons.codec.binary.Base32;
import org.json.simple.parser.ParseException;

import encryption.CryptUtil;
import signatures.SignUtil;

public class Server extends java.rmi.server.UnicastRemoteObject implements MedicalService {

    // TODO: Add docs and comments.

    // ----------------- STATUS CODES --------------//
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
    private final int INACTIVE_TIMEOUT = 408;
    private final int AUTH_REQUIRED = 511;
    private final int ERROR = 400;


    // --------------- VS CODE PATH PREFIX ------------//
    private static String prefix = ".";
    // --------------- INTELLIJ PATH PREFIX ----------//
//    private static String prefix = "src";

    private static final Logger logger = Logger.getLogger(Server.class.getName());
    private FileHandler handler;

    public Server() throws Exception {
        super();
        SimpleDateFormat sdf = new SimpleDateFormat("dd-MMM-yyyy hh-mm-ss a");
        String currentLog = sdf.format(new Date()) + ".txt";
        File file = new File(prefix + "/Logs/" + currentLog);
        
        // when someone doesn't have the Logs folder
        file.getParentFile().mkdirs();
        file.setReadOnly();
//        RecordsUtil.addUser("Joe", "Admindoe", "admin",
//                "JDoe@mediservice.com", "superUser89@pass",
//                "Admins", "BGLBEVX44CZC45IOAQI3IFJBDBEOYY3A");

        handler = new FileHandler(prefix + "/Logs/" + currentLog);
        logger.addHandler(handler);

        SimpleFormatter formatter = new SimpleFormatter();  
        handler.setFormatter(formatter);

//        addPatient(new Message("Joe", "Doe", "testUser", "MyPassword#3456", "jdoe@email.com","MAAULT5OH5P4ZAW7JC5PWJIMZZ7VWRNU"));
    }

    public SafeMessage authenticateUser(SafeMessage safeMessage) throws Exception {

        try {
            Message data = CryptUtil.decryptSafeMessage("server", safeMessage);
            // Extract data from the message
            Main client = data.getClient();
            String username = data.getUsername();
            String pass = data.getPassword();

            System.out.println("** Authenticating user: " + username);
            boolean signCorrect = challengeUser(client, username);
            Message msg = new Message(CREDENTIALS_BAD);
            if (!signCorrect) {
                logger.warning("Failed challenge : " + username);
                return prepResponse(msg, username);
            }
            logger.info("Challenged : " + username);

            System.out.println("** Validating username for : " + username);
            boolean username_valid = RecordsUtil.userExists(username);
            System.out.println("** Username valid: " + username_valid);
            int pass_valid = this.verifyPassword(username, pass);

            if (RecordsUtil.getContext(username).getLocked() == 1) {
                logger.warning("Credentials not OK : " + username);
                msg = new Message(LOCKED);
            } else if (username_valid && pass_valid == PASS_OK) {
                logger.info("Credentials OK : " + username);
                msg = new Message(CREDENTIALS_OK);
            } else if (pass_valid == LOCKED) {
                logger.warning("Credentials not OK : " + username);
                msg = new Message(LOCKED);
            }

            return prepResponse(msg, username);
        } catch (InvalidKeySpecException Ex) {
            Message msg = new Message(CREDENTIALS_BAD);
            // Log the attempt with incorrect credentials
            return prepResponse(msg, "");
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

    public int verifyPassword(String username, String pass) throws Exception {
        System.out.println("** Verifying password for user: " + username);
        int status = RecordsUtil.passMatches(username, pass);

        if (status == LOCKED) {
            // Add implementation in Server.java to lock out user using the lockUser()
            // method.
            //------------------ ALREADY IMPLEMENTED:) -------------------------------//
            System.out.println("** Password incorrect - account locked for user: " + username);
            lockUser(username);
            logger.info("PASS INCORRECT, LOCKED ACCOUNT: " + username);
            return LOCKED;
        } else if (status == CREDENTIALS_BAD) {
            System.out.println("** Password incorrect for user: " + username);
            logger.info("Password incorrect : " + username);
            return CREDENTIALS_BAD;
        }
        // else pass is ok
        logger.info("Password accepted : " + username);
        System.out.println("** Password correct for user: " + username);
        return PASS_OK;
    }

    public SafeMessage verifyCode(SafeMessage safeMessage) throws Exception {
        Message message = CryptUtil.decryptSafeMessage("server", safeMessage);
        String username = message.getUsername();
        String code = message.getPassword(); // password field can be used to carry code as well

        System.out.println("** Verifying code for user: " + username);
        int status = RecordsUtil.codeMatches(username, code);
        logger.info("Verifying code : " + username);

        if (status == LOCKED) {
            //------------------ ALREADY IMPLEMENTED:) -------------------------------//
            lockUser(username);
            System.out.println("** Incorrect code - account has been locked for user: " + username);
            logger.warning("AUTH CODE INCORRECT, ACCOUNT LOCKED : " + username);
            Message msg = new Message(LOCKED);
            return prepResponse(msg, username);
        } else if (status == CODE_INCORRECT) {
            System.out.println("** Incorrect code for user: " + username);
            logger.warning("Auth code not OK : " + username);
            Message msg = new Message(CODE_INCORRECT);
            return prepResponse(msg, username);
        }
        System.out.println("** Verification code correct for user: " + username);
        logger.info("Auth code OK : " + username);
        Context context = RecordsUtil.getContext(username);
        System.out.println();
        Message msg = new Message(CODE_CORRECT, context.getGroup());
        if (status == CODE_CORRECT) {
            RecordsUtil.login(username);
        }

        return prepResponse(msg, username);
    }

    public int addPatient(Message message) throws Exception {
        String username = message.getUsername();
        String password = message.getPassword();
        String name = message.getName();
        String email = message.getEmail();
        String surname = message.getSurname();
        String code = message.getCode();

        if (!RecordsUtil.userExists(username)) {
            RecordsUtil.addPatient(username, name, surname, email, password, code);
            register(username);
            logger.info("Registered new user : " + username);
            return REGISTRATION_SUCCESS;
        }
        logger.warning("Registration fail : " + username);
        return REGISTRATION_FAIL;
    }

     public SafeMessage addUser(SafeMessage safeMessage) throws Exception {
         Message message = CryptUtil.decryptSafeMessage("server", safeMessage);

         String issuer = message.getIssuer();
         String name = message.getName();
         String surname = message.getSurname();
         String username = message.getUsername();
         String email = name.substring(0, 1) + surname + "@mediservice.com";
         String pass = message.getPassword();
         String group = message.getGroup();
         String code = message.getCode();

         System.out.println(group);

         int inactiveOrAnauth = checkTimeoutAndActive(issuer);

         if (inactiveOrAnauth != 0) {
             Message msg1 = new Message(inactiveOrAnauth);
             return prepResponse(msg1, issuer);
         }

         Message msg = new Message(REGISTRATION_FAIL);
         if (!RecordsUtil.userExists(username)) {
             boolean status = false;
             msg = new Message(FORBIDDEN);
             status = RecordsUtil.hasPerms(issuer, RecordsUtil.CAN_REGISTER_ACCOUNTS);
             if (!status) status = RecordsUtil.hasPerms(issuer, RecordsUtil.CAN_REGISTER_PATIENTS);
             if (status) {
                 RecordsUtil.addUser(name, surname, username, email, pass, group, code);
                 register(username); // this is so that a key pair is generated
                 msg = new Message(OK);
             }
         }

         return prepResponse(msg, issuer);
     }

    public boolean strengthCheck(String input) throws Exception {
        Pattern p = Pattern.compile("[^A-Za-z0-9 ]"); // Find character not in that list
        Matcher m = p.matcher(input);

        if (m.find()) { // If a special character is found
            p = Pattern.compile("[0-9]");
            m = p.matcher(input);

            if (m.find()) {
                p = Pattern.compile("[A-Z]");
                m = p.matcher(input);

                if (m.find()) {
                    p = Pattern.compile("[a-z]");
                    m = p.matcher(input);

                    if ((m.find()) && (input.length() > 9)) return true;
                }
            }
        }
        return false;
    }

    public void register(String user) throws Exception {
        System.out.println("User created with username: " + user);
        // Generate a key pair for the newly added user
        CryptUtil.genKeyPair(CryptUtil.ALGO_NAME, user);
    }

    public boolean strengthCheck(Message m) throws Exception {
        return strengthCheck(m.getPassword());
    }

    /**
     * Generates a secret key.
     * 
     * @return a secret key used for symmetric encryption
     * @throws Exception
     */
    public String secretKeyGen() throws Exception {
        byte[] bytes = new byte[20];
        new SecureRandom().nextBytes(bytes);
        return new Base32().encodeToString(bytes);
    }

    public void logout(SafeMessage safeMessage) throws Exception {
        Message data = CryptUtil.decryptSafeMessage("server", safeMessage);
        String username = data.getUsername();
        RecordsUtil.logout(username);
    }

    public int checkTimeoutAndActive(String username) throws IOException, ParseException {
        boolean inactiveTimeout = RecordsUtil.inactiveTimeout(username);
        Context context = RecordsUtil.getContext(username);

        int status = 0;

        if (inactiveTimeout) {
            RecordsUtil.logout(username);
            status = INACTIVE_TIMEOUT;
        } else if (context.getActive() == 0) {
            status = AUTH_REQUIRED;
        }

        return status;
    }


    public SafeMessage getUsers(SafeMessage safeMessage) throws Exception {
        Message data = CryptUtil.decryptSafeMessage("server", safeMessage);

        String issuer = data.getUsername();

        int inactiveOrAnauth = checkTimeoutAndActive(issuer);

        if (inactiveOrAnauth != 0) {
            Message msg1 = new Message(inactiveOrAnauth);
            return prepResponse(msg1, issuer);
        }

        Map<String, String> users = new HashMap<>();
        boolean status = false;
        Message message = new Message(FORBIDDEN, users);
        status = RecordsUtil.hasPerms(issuer, RecordsUtil.CAN_READ_USERS);
        if (status) {
            users = RecordsUtil.readUsers();
            message = new Message(OK, users);
        }

        return prepResponse(message, issuer);
    }

    public SafeMessage getRecords(SafeMessage safeMessage) throws Exception {

        Message data = CryptUtil.decryptSafeMessage("server", safeMessage);
        // Extract data from the message
        String issuer = data.getUsername();
        String usertosee = data.getPassword(); // password field can be used to carry this this info

        // check if inactiveTimeout == true
        // if true - evict
        // else update last_active and continue


        // returns 0 if user is logged in and hasn't triggered timeout
        // else returns INACTIVE_TIMEOUT or AUTH_REQUIRED
        int inactiveOrAnauth = checkTimeoutAndActive(issuer);

        if (inactiveOrAnauth != 0) {
            Message msg1 = new Message(inactiveOrAnauth);
            return prepResponse(msg1, issuer);
        }

        String records = "";
        Message message = new Message(FORBIDDEN, records);
        boolean status = false;
        // we check if it is a Patient just accessing their own data or it is someone
        // else
        String group = RecordsUtil.getContext(issuer).getGroup();
        if (!issuer.equals(usertosee)) {
            status = RecordsUtil.hasPerms(issuer, RecordsUtil.CAN_READ_PATIENTS);
            if (status) {
                records = RecordsUtil.readPatient(usertosee);
                message = new Message(OK, records);
            }
        } else if (group.equals("Patients")) { // issuer is the same as the user to see and belongs to Patients
            records = RecordsUtil.readPatient(usertosee);
            message = new Message(OK, records);
        }

        return prepResponse(message, issuer);
    }

    // TODO: change it to hasWriteUserPerm and add a separate method for updating
    // Patients only
    public SafeMessage updateRecords(SafeMessage safeMessage) throws Exception {

        Message data = CryptUtil.decryptSafeMessage("server", safeMessage);

        // Extract data from the message
        String issuer = data.getUsername();
        String usertosee = data.getPassword(); // password field can be used to carry this this info

        int inactiveOrAnauth = checkTimeoutAndActive(issuer);

        if (inactiveOrAnauth != 0) {
            Message msg1 = new Message(inactiveOrAnauth);
            return prepResponse(msg1, issuer);
        }

        /*
         * I will not include the actual update information, so it is kind of just a
         * simulation instead I will just send a response (OK - updated, FORBIDDEN - not
         * updated, lack of permissions)
         */
        Message message = new Message(FORBIDDEN);
        boolean status = false;
        // we check if it is a Patient just accessing their own data or it is someone
        // else
        String group = RecordsUtil.getContext(issuer).getGroup();
        if (!issuer.equals(usertosee)) {
            System.out.println("Update user");
            status = RecordsUtil.hasPerms(issuer, RecordsUtil.CAN_WRITE_PATIENTS);
            if (status) {
                // here we update records and send back an OK message
                RecordsUtil.updatePatient(usertosee);
                message = new Message(OK);
            }
        } else if (group.equals("Patients")) { // issuer is the same as the user to see and belongs to Patients
            // here we update records and send back an OK message
            RecordsUtil.updatePatient(usertosee);
            message = new Message(OK);
        }

        return prepResponse(message, issuer);
    }


    public SafeMessage getGroupPerms(SafeMessage safeMessage) throws Exception {
        Message data = CryptUtil.decryptSafeMessage("server", safeMessage);

        String issuer = data.getUsername();
        String group = data.getPassword(); // can be used to carry the wanted group

        int inactiveOrAnauth = checkTimeoutAndActive(issuer);

        if (inactiveOrAnauth != 0) {
            Message msg1 = new Message(inactiveOrAnauth);
            return prepResponse(msg1, issuer);
        }

        HashSet<Long> permissions = new HashSet<>();
        boolean status = false;
        Message message = new Message(FORBIDDEN, permissions);
        status = RecordsUtil.hasPerms(issuer, RecordsUtil.CAN_READ_GROUPS);
        if (status) {
            permissions = RecordsUtil.readGroupPerms(group);
            message = new Message(OK, permissions);
        }

        return prepResponse(message, issuer);
    }

    public SafeMessage setGroupPerms(SafeMessage safeMessage) throws Exception {
        Message data = CryptUtil.decryptSafeMessage("server", safeMessage);

        String issuer = data.getUsername();
        String group = data.getGroup();

        int inactiveOrAnauth = checkTimeoutAndActive(issuer);

        if (inactiveOrAnauth != 0) {
            Message msg1 = new Message(inactiveOrAnauth);
            return prepResponse(msg1, issuer);
        }

        HashSet<Long> newPermissions = data.getPermissions();

        boolean status = false;
        Message message = new Message(FORBIDDEN);
        status = RecordsUtil.hasPerms(issuer, RecordsUtil.CAN_WRITE_GROUPS);
        if (status) {
//            System.out.println("Setting new permissions for: " + group);
            RecordsUtil.setGroupPerms(newPermissions, group);
            message = new Message(OK);
        }

        return prepResponse(message, issuer);
    }

    public SafeMessage assignToGroup(SafeMessage safeMessage) throws Exception {
        Message data = CryptUtil.decryptSafeMessage("server", safeMessage);

        String issuer = data.getUsername();
        String assignee = data.getPassword(); // pass field used to carry assignee name
        String group = data.getCode(); // code field used to carry group username

        int inactiveOrAnauth = checkTimeoutAndActive(issuer);

        if (inactiveOrAnauth != 0) {
            Message msg1 = new Message(inactiveOrAnauth);
            return prepResponse(msg1, issuer);
        }

        boolean status = false;
        Message message = new Message(FORBIDDEN);
        status = RecordsUtil.hasPerms(issuer, RecordsUtil.CAN_ASSIGN_PERMS);
        if (status) {
//            System.out.println("Setting new permissions for: " + group);
            RecordsUtil.assignToGroup(assignee, group);
            message = new Message(OK);
        }

        return prepResponse(message, issuer);

    }

    public void lockUser(String user) throws Exception {
        // Okay this is just so beautiful, can we leave it like that please hahahah ~
        // Kas
        System.out.println("SKIDADDLE SKIDOODLE THE USER " + user + " IS NOW A NOODLE");
        RecordsUtil.blockUser(user);
    }

    public static void main(String[] args) throws Exception {
        try {
            System.out.println("Starting the server...");
            MedicalService server = new Server();
            Naming.rebind("rmi://localhost/MedicalService", server);
            System.out.println("Server running at rmi://localhost/MedicalService");
        } catch (Exception e) {
            System.out.println("Server error: " + e);
        }
    }
}
