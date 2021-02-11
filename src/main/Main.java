package main;

import java.io.Serializable;
import java.nio.charset.Charset;
import java.nio.file.FileSystems;
import java.nio.file.Path;
import java.rmi.Naming;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Random;
import java.util.Scanner;

import javax.crypto.SealedObject;
import javax.crypto.SecretKey;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;

import encryption.CryptUtil;
import signatures.SignUtil;

public class Main implements Serializable {

    private static Scanner s = new Scanner(System.in);
    private static MedicalService server;
    private String tempName;
    private String tempUsername;
    private String tempSurname;
    private String tempMail;
    private static String tempPass;
    private static String firstPass;
    private int status;
    private Message msg;
    private Message response;

    private final String REGISTER = "register";
    private final String LOGIN = "login";
    private final String LOGOUT = "logout";
    private final String EXIT = "exit";

    // Patient-specific actions
    private final String MY_RECORDS = "my_records";
    private final String UPDATE_INFO = "update_info";

    // Admin-specific actions
    // some regexes
    private final String ALL_USERS = "all_users";
    private final String GET_PERMS = "get_perms\\s\\w+";
    private final String SET_PERMS = "set_perms\\s\\w+";
    private final String ASSIGN_TO_GROUP = "assign\\s\\w+";
    private final String ADD_USER = "add_user";
    private final String DEL_USER = "del_user\\s\\w+";

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
    // private final int NOT_ALLOWED = 405;
    private final int ERROR = 400;

    // TODO: Add docs and comments.

    public Main() throws Exception {
        mainScreen();
    }

    public void see_records(String issuer, String usertosee) throws Exception {
        Message msg = new Message(issuer, usertosee);
        SafeMessage safeMessage = prepMessage(msg);
        SafeMessage sealedResponse = server.getRecords(safeMessage);

        PrivateKey userPrivKey = CryptUtil.getPrivateKey(CryptUtil.ALGO_NAME, tempUsername);
        SecretKey decryptedKey = CryptUtil.decrypt(sealedResponse.getSecretKeyEncrypted(), userPrivKey);

        response = CryptUtil.decrypt(sealedResponse.getObj(), decryptedKey);
        if (response.getStatus() == FORBIDDEN) {
            System.out.println("Sorry you might not have permissions to perform this action.");
        } else if (response.getStatus() == OK) {
            // group field may be used to carry records as well as it is all strings
            System.out.println("Your medical history:\n" + response.getGroup());
        } else if (response.getStatus() == INACTIVE_TIMEOUT) {
            System.out.println("Automatic logout after an inactive period:\n");
            exit();
        } else if (response.getStatus() == AUTH_REQUIRED) {
            System.out.println("You are not logged in!");
            exit();
        }
    }

    public void update_records(String issuer, String usertoupdate) throws Exception {
        Message msg = new Message(issuer, usertoupdate);
        SafeMessage safeMessage = prepMessage(msg);
        SafeMessage sealedResponse = server.updateRecords(safeMessage);

        PrivateKey userPrivKey = CryptUtil.getPrivateKey(CryptUtil.ALGO_NAME, tempUsername);
        SecretKey decryptedKey = CryptUtil.decrypt(sealedResponse.getSecretKeyEncrypted(), userPrivKey);

        response = CryptUtil.decrypt(sealedResponse.getObj(), decryptedKey);
        if (response.getStatus() == FORBIDDEN) {
            System.out.println("Sorry you might not have permissions to perform this action.");
        } else if (response.getStatus() == OK) {
            // group field may be used to carry records as well as it is all strings
            System.out.println("Records updated successfully for user: " + usertoupdate);
        } else if (response.getStatus() == INACTIVE_TIMEOUT) {
            System.out.println("Automatic logout after an inactive period:\n");
            exit();
        } else if (response.getStatus() == AUTH_REQUIRED) {
            System.out.println("You are not logged in!");
            exit();
        }
    }

    public void menuScreenAdmin(String username) throws Exception {
        System.out.println("\n1. Type 'all_users' to get user's usernames and their corresponding groups.");
        System.out.println("2. Type 'get_perms <group>' to see permissions associated with a specific group.");
        System.out.println("3. Type 'set_perms <groups>' to assign new permissions to a specific group.");
        System.out.println("4. Type 'assign <username> <group>' to assign a user to a specific group.");
        System.out.println("5. Type 'add_user' to register a new user.");
        System.out.println("6. Type 'del_user <username>' to delete an account.");
        System.out.println("7. Type 'logout' to end the session.");

        String action = userInput();

        if (action.matches(ALL_USERS)) {
            getUsers(username);
        } else if (action.matches(GET_PERMS)) {
            ;
        } else if (action.matches(SET_PERMS)) {
            ;
        } else if (action.matches(ASSIGN_TO_GROUP)) {
            ;
        } else if (action.matches(ADD_USER)) {
            ;
        } else if (action.matches(DEL_USER)) {
            ;
        } else if (action.matches(LOGOUT)) {
            logout();
        } else {
            menuScreenAdmin(username);
        }
    }

    public void getUsers(String issuer) {
        ;
    }

    public void menuScreenStaff(String username) {
        ;
    }

    public void menuScreenPatient(String username) throws Exception {
        System.out.println("\n1. Type 'my_records' to see your medical history.");
        System.out.println("2. Type 'update_info' to update your contact information.");
        System.out.println("3. Type 'logout' to end the session.");

        String action = userInput();

        switch (action) {
            case MY_RECORDS:
                see_records(username, username);
                menuScreenPatient(username);
                break;
            case LOGOUT:
                logout();
                break;
            case UPDATE_INFO:
                update_records(username, username);
                menuScreenPatient(username);
                break;
            default:
                menuScreenPatient(username);
                break;
        }
    }

    public void mainScreen() throws Exception {
        System.out.println("\nWelcome to the Medical Portal!");
        System.out.println("1. Type 'register' to join the MedicalService.");
        System.out.println("2. Type 'login' to sign in to the service");
        System.out.println("3. Type 'exit' to quit the service.");
        System.out.print("\n> ");

        switch (s.nextLine()) {
            case REGISTER:
                register();
                break;
            case LOGIN:
                login();
                break;
            case EXIT:
                exit();
                break;
            default:
                mainScreen();
                break;
        }
    }

    private void logout() throws Exception {
        msg = new Message(tempUsername, null);
        SafeMessage safeMessage = prepMessage(msg);

        server.logout(safeMessage);
        tempUsername = null;
        mainScreen();
    }

    private void exit() {
        System.out.println("Exiting the MedicalService...");
        System.out.println("See you next time!");
        System.exit(0);
    }

    private String userInput() {
        System.out.print("> ");
        return s.nextLine();
    }

    /**
     * Displays a screen prompting for a username and password as well as a secret
     * code to authenticate a party requesting access. Sends requested credentials
     * to the server for authentication/ verification reasons. Upon successful
     * authentication/ verification obtains the records of the party requesting
     * access. TODO: Add something so that a user can go back to the main menu -->
     * no for now
     * 
     * @throws Exception
     */
    private void login() throws Exception {
        System.out.println("\nLOGIN SYSTEM\n\nEnter username: ");
        tempUsername = userInput();
        System.out.println("Enter password:");
        tempPass = userInput();

        boolean itsServer = authenticateServer();
        if (!itsServer) {
            System.out.println("Burn your hard drive and run away cos it is not the MedicalService");
            System.exit(0);
        }
        msg = new Message(tempUsername, tempPass, this);
        /*
         * to be fair for simplicity we will use the same key pair, but need to include
         * in the report that in the production normally there would be a different key
         * pair
         */
        SafeMessage encryptedMsg = prepMessage(msg);
        SafeMessage sealedResponse = server.authenticateUser(encryptedMsg);

        PrivateKey userPrivKey = CryptUtil.getPrivateKey(CryptUtil.ALGO_NAME, tempUsername);
        SecretKey decryptedKey = CryptUtil.decrypt(sealedResponse.getSecretKeyEncrypted(), userPrivKey);

        response = CryptUtil.decrypt(sealedResponse.getObj(), decryptedKey);
        if (response.getStatus() == CREDENTIALS_OK) {
            response = takeCode(); // proceed with code verification
            status = response.getStatus();
            while (status == CODE_INCORRECT) {
                System.out.println("\n\n<Code incorrect, please try again.>");
                response = takeCode();
                status = response.getStatus();
            }

            checkLocked(status); // check if the account has been locked
            // Finally if everything went gucci display the screen corresponding to the user
            // group
            if (status == CODE_CORRECT) {
                System.out.print("\n\nWELCOME BACK " + tempUsername);
                // helper
                // System.out.print("Your group: " + response.getGroup());
                switch (response.getGroup()) {
                    case "Patients":
                        menuScreenPatient(tempUsername);
                    case "Admins":
                        menuScreenAdmin(tempUsername);
                        // case "Nurses": menuScreenStaff(tempUsername);
                        // case "Doctors": menuScreenStaff(tempUsername);
                        // case "Receptionists": menuScreenStaff(tempUsername);
                    default:
                        exit();
                }
            }
        } else if (response.getStatus() == CREDENTIALS_BAD) {
            System.out.println("\n\n<Login error - incorrect credentials.>");
            login();
        } else {
            System.out.println("\n\n<There is an impostor among us.>");
            checkLocked(response.getStatus());
        }
    }

    private void checkLocked(int status) {
        if (status == LOCKED) {
            // Add implementation in Server.java to lock out user using the lockUser()
            // method.
            System.out.println(
                    "This account has been locked. Please contact the system administrator to unlock your account.");
            System.exit(0);
        }
    }

    // TODO: fuck that we don't have time
    // TODO: might want to redesign so that users do not choose the username
    // themselves but are rather assigned some IDs
    private void register() throws Exception {
        System.out.println("\nREGISTRATION SYSTEM\n\nEnter your first name:");
        // Username input
        tempName = userInput();
        System.out.println("\n\nEnter your last name:");
        tempSurname = userInput();
        System.out.println("\n\nEnter your email:");
        tempMail = userInput();
        String pass = takeNewPass();
        System.out.println("\n\nEnter a username you would like to use:");
        tempUsername = userInput();

        // https://security.stackexchange.com/questions/45594/should-users-password-strength-be-assessed-at-client-or-at-server-side
        if(server.strengthCheck(new Message(null, pass))) {
            String code = setUpAuthentication();
            Message msg = new Message(tempName, tempSurname, tempUsername, pass, tempMail, code);
            int status = server.addPatient(msg);
            System.out.println("\n\nWOHOO REGISTRATION SUCCESSFUL!");
            mainScreen();
        } else {
            System.out.println("\nAn account with those credentials may already exist or your password is too weak.");
            System.out.println("Please ensure your password includes all requirements: ");
            System.out.println("At least 1 lowercase character");
            System.out.println("At least 1 uppercase character");
            System.out.println("At least 1 number");
            System.out.println("At least 1 special character");
            System.out.println("At least 10 characters");
            register();
        }
    }

    public String takeNewPass() throws Exception { // registration password
        // Password input
        System.out.println("Enter password: ");
        firstPass = userInput();
        System.out.println("Confirm password: ");
        tempPass = userInput();

        while (!firstPass.equals(tempPass)) {
            System.out.println("\nPasswords do not match\n");
            System.out.println("Enter password: ");
            firstPass = userInput();
            System.out.println("Confirm password: ");
            tempPass = userInput();
        }
        return tempPass;
    }

    private SafeMessage prepMessage(Message msg) throws Exception {
        PublicKey serverPublicKey = CryptUtil.getPublicKey(CryptUtil.ALGO_NAME, "server");
        SecretKey newKey = CryptUtil.genSecretKey();
        SealedObject response = CryptUtil.encrypt(msg, newKey);
        byte[] encryptedKey = CryptUtil.encrypt(newKey, serverPublicKey);

        return new SafeMessage(response, encryptedKey);
    }

    private Message takeCode() throws Exception { // login auth
        System.out.println("\nPlease enter your 6-digit authentication code:");
        System.out.println("--> Type 'none' if you don't have one"); // dummy value tbf as it is not checked
        // System.out.println("Type 'cancel' to go back to the main menu.");
        String code = userInput();
        msg = new Message(tempUsername, code);
        SafeMessage safeMessage = prepMessage(msg);

        SafeMessage encryptedResponse = server.verifyCode(safeMessage);
        PrivateKey userPrivKey = CryptUtil.getPrivateKey(CryptUtil.ALGO_NAME, tempUsername);
        SecretKey decryptedKey = CryptUtil.decrypt(encryptedResponse.getSecretKeyEncrypted(), userPrivKey);

        Message response = CryptUtil.decrypt(encryptedResponse.getObj(), decryptedKey);
        return response;
    }

    private String setUpAuthentication() throws Exception { // registration auth
        System.out.println("\nWould you like to set up Two Factor Authentication? (yes/no)");
        String key = "none";
        while (true) {
            String cmd = userInput();
            if (cmd.equals("yes")) {
                key = server.secretKeyGen();
                createQRimage(tempUsername, key);
                System.out.println("\nPlease scan the picture displayed.");

                // ------------------------------- FOR WINDOWS
                // -----------------------------------//
//                String command = "cmd.exe /c start " + "./" + tempUsername + "_QRcode.png";
                // ------------------------------- FOR LINUX --------------------------------//
                 String command = "xdg-open " + tempUsername + "_QRcode.png";

                Runtime.getRuntime().exec(command);
                System.out.println("Alternatively, enter this code on your authenticator app:\n" + key);
                break;
            } else if (cmd.equals("no")) {
                System.out.println("Understandable, have a nice day."); // lol Trump would appreciate
                break;
            }
            // System.out.println("Please enter 'yes' or 'no'");
        }
        // Runtime.getRuntime().exec("cmd /c start del /S *.png"); //will delete all
        // .png files in current dir (will implement later on)
        return key;
    }

    public void createQRimage(String username, String code) throws Exception {
        String content = "otpauth://totp/MedicalPortal: " + username + "?secret=" + code
                + "&algorithm=SHA1&digits=6&period=30";
        BitMatrix matrix = new QRCodeWriter().encode(content, BarcodeFormat.QR_CODE, 200, 200);
        Path path = FileSystems.getDefault().getPath("./" + username + "_QRcode.png");
        MatrixToImageWriter.writeToPath(matrix, "PNG", path);
    }

    public String signChallenge(String challenge) throws Exception {
        // System.out.println(tempName);
        PrivateKey privKey = CryptUtil.getPrivateKey(CryptUtil.ALGO_NAME, tempUsername);
        String signed = SignUtil.signChallenge(challenge, privKey);
        return signed;
    }

    public boolean authenticateServer() throws Exception {
        byte[] array = new byte[Server.CHALLENGE_LEN];
        new Random().nextBytes(array);
        String challenge = new String(array, Charset.forName("UTF-8"));
        String signed = server.signChallenge(challenge);
        PublicKey pubKey = CryptUtil.getPublicKey(CryptUtil.ALGO_NAME, "server");
        boolean signCorrect = SignUtil.verifyChallenge(signed, challenge, pubKey);

        return signCorrect;
    }

    public static void main(String[] args) throws Exception {
        try {
            server = (MedicalService) Naming.lookup("rmi://localhost/MedicalService");
            new Main();
        } catch (Exception e) {
            System.out.println("Server exception: " + e);
        }
    }
}