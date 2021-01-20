import java.rmi.*;
import java.util.*;

public class Main
{
    private static Scanner s = new Scanner(System.in);
    private static MedicalService server;
    private static String tempName;
    private static String tempPass;
    private static String firstPass;
    private static int tries;

    public Main() throws Exception
    {
        System.out.println("Welcome to the Medical Portal!\nWould you like to 'register' or 'login'?");
        while(true)
        {
            switch(s.nextLine()) {
                case "register": register(); break;
                case "login": login(); break;
                default: System.out.println("Please enter either 'register' or 'login'"); break;
            }
        }
    }

    private void login() throws Exception
    {
        System.out.println("LOGIN SYSTEM\n\nEnter username: ");
        tempName = s.nextLine();

        while(!server.userExists(tempName)) 
        {
            System.out.println("This username does not exist. Please try again.");
            tempName = s.nextLine();
        }

        User user = server.retrieveUser(tempName);
        System.out.println("Enter password:");
        tempPass = s.nextLine();
        
        tries = 2;
        while(!tempPass.equals(user.password) && tries > 0)
        {
            System.out.println("Password incorrect. Please try again. " + tries + " tries remaining.");
            tempPass = s.nextLine();
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
            System.out.println("Please enter your 6-digit authentication code:");
            String tempCode = s.nextLine();

            tries = 2;
            while(!tempCode.equals(server.TOTPcode(user.secretCode)) && tries > 0)
            {
                System.out.println("Code incorrect. Please try again. " + tries + " tries remaining.");
                tempCode = s.nextLine();
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
        System.out.println("REGISTRATION SYSTEM\n\nEnter username:");
        tempName = s.nextLine();

        while(server.userExists(tempName))
        {
            System.out.println("\nUsername is already taken.\n\nPlease enter a new username:");
            tempName = s.nextLine();
        }

        System.out.println("Enter password: ");
        firstPass = s.nextLine();

        System.out.println("Confirm password: ");

        while(!firstPass.equals(s.nextLine()))
        {
            System.out.println("\nPasswords do not match.\n\nPlease enter your password.");
            firstPass = s.nextLine();
            System.out.println("Confirm password: ");
        }

        server.receivedRegistration(tempName, firstPass);
        System.out.println("User added. Would you like to set up Two Factor Authentication? (yes/no)");
        while(true)
        {
            String cmd = s.nextLine();
            if(cmd.equals("yes")) {
                System.out.println("Please enter this code on your authenticator app:\n" + server.secretKeyGen());
                break;
            } else if(cmd.equals("no")) {
                System.out.println("Understandable, have a nice day.");
            }
            System.out.println("Please enter 'yes' or 'no'");
        }
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