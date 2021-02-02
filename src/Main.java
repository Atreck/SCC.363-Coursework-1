import signatures.SignUtil;

import java.io.Serializable;
import java.nio.charset.Charset;
import java.rmi.*;
import java.security.*;
import java.util.*;

public class Main implements Serializable {

    private static Scanner s = new Scanner(System.in);
    private static MedicalService server;
    private String tempName;
    private static String tempPass;
    private static String firstPass;
    private int status;
    private Message msg;
    private Message response;
    private User currentUser;
    private Boolean denied;
    private int fakeTries = 2;

    private final String REGISTER = "register";
    private final String LOGIN = "login";
    private final String EXIT = "exit";

    private final int CREDENTIALS_OK = 2;
    private final int CREDENTIALS_BAD = 3;
    private final int CODE_INCORRECT = 4;
    private final int CODE_CORRECT = 5;
    private final int LOCKED = 8;

    //TODO: Add docs and comments.

    public Main() throws Exception {
        mainScreen();
    }


    public void mainScreen() throws Exception {
        System.out.println("\nWelcome to the Medical Portal!");
        System.out.println("1. Type 'register' to join the MedicalService.");
        System.out.println("2. Type 'login' to sign in to the service");
        System.out.println("3. Type 'exit' to quit the service.");
        System.out.print("\n> ");

        switch(s.nextLine()) {
            case REGISTER: register(); break;
            case LOGIN: login(); break;
            case EXIT: exit(); break;
            default: mainScreen(); break;
        }
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
     * Displays a screen prompting for a username and password as well
     * as a secret code to authenticate a party requesting access.
     * Sends requested credentials to the server for authentication/ verification
     * reasons. Upon successful authentication/ verification obtains the records
     * of the party requesting access.
     * TODO: Add something so that a user can go back to the main menu - yes/ no?
     * TODO: Add client authenticating server?
     * @throws Exception
     */
    private void login() throws Exception {
        denied = false;
        System.out.println("\nLOGIN SYSTEM\n\nEnter username: ");
        tempName = userInput();
        System.out.println("Enter password:");
        tempPass = userInput();

        boolean itsServer = authenticateServer();
        if (!itsServer) {
            System.out.println("Burn your hard drive and run away cos it is not the MedicalService");
            System.exit(0);
        }
        msg = new Message(tempName, tempPass, this);
        //TODO: encrypt the message (another keypair will be needed bleh)
        /*to be fair for simplicity we will use the same key pair, but need to
        *include in the report that in the production normally there would be a different key pair
         */
        response = server.authenticateUser(msg);
        if (response.getStatus() == CREDENTIALS_OK) {
            response = takeCode();      // proceed with code verification
            status = response.getStatus();
            while (status == CODE_INCORRECT) {
                System.out.println("\n\n<Code incorrect, please try again.>");
                response = takeCode();
                status = response.getStatus();
            }

            checkLocked(status);       // check if the account has been locked
            // Finally if everything went gucci obtain the user object for the requested user
            if (status == CODE_CORRECT) {
                this.currentUser = response.getUser();
                System.out.println("Welcome " + currentUser.getUsername() + "!");
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
            //Add implementation in Server.java to lock out user using the lockUser() method.
            System.out.println("This account has been locked. Please contact the system administrator to unlock your account.");
            System.exit(0);
        }
    }

    // TODO: might want to redesign so that users do not choose the username themselves but are rather assigned some IDs
    private void register() throws Exception
    {
        denied = false;
        System.out.println("\nREGISTRATION SYSTEM\n\nEnter username:");
        // Username input
        tempName = userInput();
        // https://security.stackexchange.com/questions/45594/should-users-password-strength-be-assessed-at-client-or-at-server-side
        Message msg = new Message(tempName, null);
        response = server.validateUsername(msg);
        if (response.isValid()) { takeNewPass(); }
        else {
            denied = true;
            takeNewPass();
        }
    }

    public void takeNewPass() throws Exception {    //registration password
        // Password input
        System.out.println("Enter password: ");
        firstPass = userInput();
        System.out.println("Confirm password: ");
        tempPass = userInput();

        if(!firstPass.equals(tempPass)) {
            System.out.println("\nPasswords do not match\n");
            takeNewPass();
        }

        msg = new Message(null, tempPass);
        response = server.validatePassword(msg);
        if (response.isValid() && !denied)
            setUpAuthentication();
        else {
            System.out.println("\nInvalid username/password");
            System.out.println("Please ensure your password includes all requirements: ");
            System.out.println("At least 1 lowercase character");
            System.out.println("At least 1 uppercase character");
            System.out.println("At least 1 number");
            System.out.println("At least 1 special character");
            System.out.println("At least 10 characters");
            register();
        }
    }

    private Message takeCode() throws Exception {   //login auth
        System.out.println("\nPlease enter your 6-digit authentication code:");
        System.out.println("--> Type 'none' if you don't have one");        // dummy value tbf as it is not checked
//        System.out.println("Type 'cancel' to go back to the main menu.");
        String code = userInput();
        msg = new Message(tempName, code);
        response = server.verifyCode(msg);

        return response;
    }

    private void setUpAuthentication() throws Exception {   //registration auth
        System.out.println("\nRegistration successful. Would you like to set up Two Factor Authentication? (yes/no)");
        String key = null;
        while(true) {
            String cmd = userInput();
            if(cmd.equals("yes")) {
                key = server.secretKeyGen();
                msg = new Message(tempName, tempPass, key);
                server.createQRimage(msg);
                
                System.out.println("\nPlease scan the picture displayed.");
                Runtime.getRuntime().exec("cmd.exe /c start " + "./" + msg.getUsername() + "_QRcode.png");
                System.out.println("Alternatively, enter this code on your authenticator app:\n" + key);
                break;
            } else if(cmd.equals("no")) {
                System.out.println("Understandable, have a nice day.");     // lol Trump would appreciate
                msg = new Message(tempName, tempPass, key);
                break;
            }
//            System.out.println("Please enter 'yes' or 'no'");
        }
        // Runtime.getRuntime().exec("cmd /c start del /S *.png");  //will delete all .png files in current dir (will implement later on)
        server.addUser(msg);
        mainScreen();
    }

    public String signChallenge(String challenge) throws Exception {
//        System.out.println(tempName);
        PrivateKey privKey = SignUtil.retrieveKeys(tempName, SignUtil.ALGO_NAME).getPrivate();
        String signed = SignUtil.signChallenge(challenge, privKey);
        return signed;
    }

    public boolean authenticateServer() throws Exception {
        byte[] array = new byte[Server.CHALLENGE_LEN];
        new Random().nextBytes(array);
        String challenge = new String(array, Charset.forName("UTF-8"));
        String signed = server.signChallenge(challenge);
        PublicKey pubKey = SignUtil.retrieveKeys("server", SignUtil.ALGO_NAME).getPublic();
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