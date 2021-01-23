import java.awt.*;
import java.awt.desktop.SystemSleepEvent;
import java.rmi.*;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class Main
{
    private static Scanner s = new Scanner(System.in);
    private static MedicalService server;
    private static String tempName;
    private static String tempPass;
    private static String firstPass;
    private static int tries;

    private final String REGISTER = "register";
    private final String LOGIN = "login";
    private final String EXIT = "exit";

    //TODO: Add docs and comments.

    public Main() throws Exception {
        mainScreen();
    }


    public void mainScreen() throws Exception
    {
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

    private void exit()
    {
        System.out.println("Exiting the MedicalService...");
        System.out.println("See you next time!");
        System.exit(0);
    }

    private String userInput()
    {
        System.out.print("> ");
        String input = s.nextLine();
        return input;
    }

    /**
     * TODO: Break it down into for example username, password, code validation.
     * TODO: Maybe add different status codes? "If username, etc valid --> return 1" if status 1 --> bring the user records screen, else print unsuccessful and go back to the main screen?
     * TODO: Add something so that a user can go back to the main menu.
     * @throws Exception
     */
    private void login() throws Exception
    {
        System.out.println("\nLOGIN SYSTEM\n\nEnter username: ");
        tempName = userInput();

        while(!server.userExists(tempName)) 
        {
            System.out.println("This username does not exist. Please try again.");
            tempName = s.nextLine();
        }

        User user = server.retrieveUser(tempName);
        System.out.println("Enter password:");
        tempPass = userInput();
        
        tries = 2;
        while(!tempPass.equals(user.password) && tries > 0)
        {
            System.out.println("Password incorrect. Please try again. " + tries + " tries remaining.");
            tempPass = userInput();
            if(tempPass.equals(user.password)) { break; }
            tries--;

            if(tries == 0)
            {
                System.out.println("This account has been locked. Please contact the system administrator to unlock your account."); //Add implementation in Server.java to lock out user using the lockUser() method.
                server.lockUser(tempName);
                System.exit(0);
            }
        }

        if(user.secretCode != null)
        {
            System.out.println("\nPlease enter your 6-digit authentication code:");
            System.out.println("Type 'cancel' to go back to the main menu.");
            String tempCode = userInput();

            tries = 2;
            while(!tempCode.equals(server.TOTPcode(user.secretCode)) && tries > 0)
            {
                System.out.println("Code incorrect. Please try again. " + tries + " tries remaining.");
                tempCode = userInput();
                if(tempCode.equals(server.TOTPcode(user.secretCode))) { break; }
                tries--;

                if(tries == 0)
                {
                    System.out.println("This account has been locked. Please contact the system administrator to unlock your account."); //Add implementation in Server.java to lock out user using the lockUser() method.
                    server.lockUser(tempName);
                    System.exit(0);
                }
            }
        }
        System.out.println("LOGGED IN");
    }

    private void register() throws Exception
    {
        System.out.println("\nREGISTRATION SYSTEM\n\nEnter username:");
        tempName = userInput();

        while(server.userExists(tempName))
        {
            System.out.println("\nUsername is already taken.\n\nPlease enter a new username:");
            tempName = userInput();
        }

        System.out.println("Enter password: ");
        firstPass = userInput();

        // PASSWORD STRENGTH CHECK
        while(!strengthCheck(firstPass))
        {
            System.out.println("Enter password: ");
            firstPass = userInput();
        }
        

        System.out.println("Confirm password: ");

        while(!firstPass.equals(s.nextLine()))
        {
            System.out.println("\nPasswords do not match.\n\nPlease enter your password.");
            firstPass = userInput();
            System.out.println("Confirm password: ");
        }

        // Salt and Hash accepted password
        MessageDigest digest;

        try {

            digest = MessageDigest.getInstance("SHA-256");
        } catch (Exception e) {
            //TODO: handle exception
            return;
        }

        SecureRandom random = new SecureRandom();

        byte[] salt = new byte[16];
        random.nextBytes(salt);

        digest.update(salt);

        byte[] hashed = digest.digest(firstPass.getBytes(StandardCharsets.UTF_8));

        StringBuilder stringBuilder = new StringBuilder();
        for (byte b : hashed)
            stringBuilder.append(String.format("%02x", b));

        String encodedPassword = stringBuilder.toString();

        // encoded password and salt to be stored

        server.receivedRegistration(tempName, encodedPassword);
        System.out.println("\nRegistration successful. Would you like to set up Two Factor Authentication? (yes/no)");
        while(true)
        {
            String cmd = userInput();
            if(cmd.equals("yes")) {
                System.out.println("Please enter this code on your authenticator app:\n" + server.secretKeyGen());
                break;
            } else if(cmd.equals("no")) {
                System.out.println("Understandable, have a nice day.");
                break;
            }
//            System.out.println("Please enter 'yes' or 'no'");
        }
        mainScreen();
    }

    private boolean strengthCheck(String input)
    {
        Pattern p = Pattern.compile("[^A-Za-z0-9 ]"); // Find character not in that list
        Matcher m = p.matcher(input);

        if (m.find()) // If a special character is found
        {
            p = Pattern.compile("[0-9]");
            m = p.matcher(input);

            if (m.find())
            {
                p = Pattern.compile("[A-Z]");
                m = p.matcher(input);

                if (m.find())
                {
                    p = Pattern.compile("[a-z]");
                    m = p.matcher(input);

                    if ((m.find()) && (input.length() > 10))
                    {
                        return true;
                    }
                }

            }
        }

        System.out.println("Please ensure your password includes all requirements: ");
        System.out.println("At least 1 lowercase character");
        System.out.println("At least 1 uppercase character");
        System.out.println("At least 1 number");
        System.out.println("At least 1 special character");
        System.out.println("At least 10 characters");
        return false;

    }


    public static void main(String[] args) throws Exception
    {
        try {
            server = (MedicalService) Naming.lookup("rmi://localhost/MedicalService");
            new Main();
        } catch (Exception e) {
            System.out.println("Server exception: " + e);
        }
    }
}