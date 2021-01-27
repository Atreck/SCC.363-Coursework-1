package supercool363;

import signatures.SignatureUtil;

import java.io.Serializable;
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

    private final int PASS_INCORRECT = 2;
    private final int PASS_CORRECT = 3;
    private final int CODE_INCORRECT = 4;
    private final int CODE_CORRECT = 5;
    private final int SIGN_CORRECT = 6;
    private final int SIGN_INCORRECT = 7;
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
        System.out.println("\nLOGIN SYSTEM\n\nEnter username: ");
        denied = false;
        tempName = userInput();

        msg = new Message(tempName, null);
        response = server.validateUsername(msg);
        if (response.isValid())    // meaning username does not exist
            denied = true;
        else {
            msg = new Message(tempName, null, this);

            response = server.authenticateUser(msg);
            status = response.getStatus();
        }
        if (status == SIGN_CORRECT | denied) {
            // Add server challenge as well?
            // Proceed to password verification
            response = takePass();
            status = response.getStatus();
            while (status == PASS_INCORRECT | denied) {
                System.out.println("Invalid username/password. Tries remaining: " + response.getTries());
                response = takePass();
                status = response.getStatus();
            }
            
            checkLocked(status);        //check if the account hasn't been locked
            response = takeCode();      // proceed with code verification
            status = response.getStatus();
            while (status == CODE_INCORRECT) {
                System.out.println("Code incorrect, please try again. Tries remaining: " + response.getTries());
                response = takeCode();
                status = response.getStatus();
            }

            checkLocked(status);       // check again if the account has not been locked
            // Finally if everything went gucci obtain the user object for the requested user
            if (status == CODE_CORRECT) {
                this.currentUser = response.getUser();
                System.out.println("Welcome " + currentUser.getUsername() + "!");
            }

        } else if (status == SIGN_INCORRECT) {
            //Love it <3
            System.out.println("There is an impostor among us.");
        }
    }

    private void checkLocked(int status) {
        if (status == LOCKED) {
            //Add implementation in Server.java to lock out user using the lockUser() method.
            System.out.println("This account has been locked. Please contact the system administrator to unlock your account.");
            System.exit(0);
        }
    }

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

    private Message takePass() throws Exception {   //login password
        System.out.println("Enter password:");
        tempPass = userInput();

        if(!denied) {
            msg = new Message(tempName, tempPass);
            response = server.verifyPassword(msg);
        } else {
            if(fakeTries == 0)
                checkLocked(LOCKED);
            response = new Message(PASS_INCORRECT, fakeTries--);
        }
        return response;
//        System.out.println("LOGGED IN");
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
        System.out.println(tempName);
        PrivateKey privKey = SignatureUtil.retrieveKeys(tempName, SignatureUtil.ALGO_NAME).getPrivate();
        String signed = SignatureUtil.signChallenge(challenge, privKey);
        return signed;
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