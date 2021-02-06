package main;

import encryption.CryptUtil;
import signatures.SignUtil;

import javax.crypto.SealedObject;
import javax.crypto.SecretKey;
import java.io.IOException;
import java.io.Serializable;
import java.nio.charset.Charset;
import java.rmi.*;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.*;

public class Frontend implements Serializable {
    private static final long serialVersionUID = 1L;
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
    
    Frontend() {
        try {
            server = (MedicalService) Naming.lookup("rmi://localhost/MedicalService");
        } catch (Exception e) {
            System.out.println("Server exception: " + e);
        }
    }

    Boolean login(String user, String pass, String code) throws Exception {
        denied = false;
        if (!authenticateServer()) {
            System.out.println("Burn your hard drive and run away cos it is not the MedicalService");
            System.exit(0);
        }
        msg = new Message(user, pass, this);
        //TODO: encrypt the message (another keypair will be needed bleh)
        /*to be fair for simplicity we will use the same key pair, but need to
        *include in the report that in the production normally there would be a different key pair
         */
        SafeMessage encryptedMsg = prepMessage(msg);
        SafeMessage sealedResponse = server.authenticateUser(encryptedMsg);

        PrivateKey userPrivKey = CryptUtil.getPrivateKey(CryptUtil.ALGO_NAME, tempName);
        SecretKey decryptedKey = CryptUtil.decrypt(sealedResponse.getSecretKeyEncrypted(), userPrivKey);

        response = CryptUtil.decrypt(sealedResponse.getObj(), decryptedKey);
        if (response.getStatus() == CREDENTIALS_OK) {
            response = takeCode(code);      // proceed with code verification
            status = response.getStatus();
            while (status == CODE_INCORRECT) {
                System.out.println("\n\n<Code incorrect, please try again.>");
                response = takeCode(code);
                status = response.getStatus();
            }

            checkLocked(status);       // check if the account has been locked
            // Finally if everything went gucci obtain the user object for the requested user
            if (status == CODE_CORRECT) {
                this.currentUser = response.getUser();
                System.out.println("Welcome " + currentUser.getUsername() + "!");
                return true;
            }
        } else if (response.getStatus() == CREDENTIALS_BAD) {
            System.out.println("\n\n<Login error - incorrect credentials.>");
        } else {
            System.out.println("\n\n<There is an impostor among us.>");
            checkLocked(response.getStatus());
        }

        return false;
    }

    private void checkLocked(int status) {
        if (status == LOCKED) {
            //Add implementation in Server.java to lock out user using the lockUser() method.
            System.out.println("This account has been locked. Please contact the system administrator to unlock your account.");
            System.exit(0);
        }
    }

    // TODO: might want to redesign so that users do not choose the username themselves but are rather assigned some IDs
    Boolean register(String user, String pass, String confirm) throws Exception
    {
        denied = false;
        System.out.println("\nREGISTRATION SYSTEM\n\nEnter username:");
        // https://security.stackexchange.com/questions/45594/should-users-password-strength-be-assessed-at-client-or-at-server-side
        Message msg = new Message(user, null);
        response = server.validateUsername(msg);
        if (!response.isValid())
            denied = true;

        return takeNewPass(pass, confirm);
    }

    Boolean takeNewPass(String pass, String confirm) throws Exception {    //registration password
        if(!pass.equals(confirm)) {
            System.out.println("\nPasswords do not match\n");
            return false;
        }

        msg = new Message(null, confirm);
        response = server.validatePassword(msg);
        if (response.isValid() && !denied)
            return true;
        System.out.println("\nInvalid username/password");
        System.out.println("Please ensure your password includes all requirements: ");
        System.out.println("At least 1 lowercase character");
        System.out.println("At least 1 uppercase character");
        System.out.println("At least 1 number");
        System.out.println("At least 1 special character");
        System.out.println("At least 10 characters");
        return false;
    }

    private SafeMessage prepMessage(Message msg) throws Exception {
        PublicKey serverPublicKey = CryptUtil.getPublicKey(CryptUtil.ALGO_NAME, "server");
        SecretKey newKey = CryptUtil.genSecretKey();
        SealedObject response = CryptUtil.encrypt(msg, newKey);
        byte[] encryptedKey = CryptUtil.encrypt(newKey, serverPublicKey);

        return new SafeMessage(response, encryptedKey);
    }

    Message takeCode(String code) throws Exception {   //login auth
        msg = new Message(tempName, code);
        SafeMessage safeMessage = prepMessage(msg);

        SafeMessage encryptedResponse = server.verifyCode(safeMessage);
        PrivateKey userPrivKey = CryptUtil.getPrivateKey(CryptUtil.ALGO_NAME, tempName);
        SecretKey decryptedKey = CryptUtil.decrypt(encryptedResponse.getSecretKeyEncrypted(), userPrivKey);

        Message response = CryptUtil.decrypt(encryptedResponse.getObj(), decryptedKey);
        return response;
    }

    void setUpAuthentication(String response) throws Exception {   //registration auth
        System.out.println("\nRegistration successful. Would you like to set up Two Factor Authentication? (yes/no)");
        String key = null;
        while(true) {
            if(response.equals("yes")) {
                key = server.secretKeyGen();
                msg = new Message(tempName, tempPass, key);
                server.createQRimage(msg);
                
                System.out.println("\nPlease scan the picture displayed.");
                Runtime.getRuntime().exec("cmd.exe /c start " + "./" + msg.getUsername() + "_QRcode.png");
                System.out.println("Alternatively, enter this code on your authenticator app:\n" + key);
                break;
            } else if(response.equals("no")) {
                System.out.println("Understandable, have a nice day.");     // lol Trump would appreciate
                msg = new Message(tempName, tempPass, key);
                break;
            }
        }
        // Runtime.getRuntime().exec("cmd /c start del /S *.png");  //will delete all .png files in current dir (will implement later on)
        server.addUser(msg);
    }

    public String signChallenge(String challenge) throws Exception {
//        System.out.println(tempName);
        PrivateKey privKey = CryptUtil.getPrivateKey(CryptUtil.ALGO_NAME, tempName);
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
}