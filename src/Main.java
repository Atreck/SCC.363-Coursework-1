import java.awt.*;
import java.awt.desktop.SystemSleepEvent;
import java.rmi.*;
import java.util.*;

public class Main
{
    private static Scanner s = new Scanner(System.in);
    private static MedicalService server;
    private static String tempName;
    private static String tempPass;
    private static String firstPass;

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
        System.out.println("Type the number of the action you would like to undertake:");
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
     * TODO: Break it down into for example usernmae, password, code validation.
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
        System.out.println(user.password);
        System.out.println("Enter password:");
        tempPass = userInput();

        while(!tempPass.equals(user.password)) //Add counter. Max 5 tries.
        {
            System.out.println("Password incorrect. Please try again.");
            tempPass = s.nextLine();
        }
        if(user.secretCode != null)
        {
            System.out.println("\nPlease enter your 6-digit authentication code:");
            System.out.println("Type 'cancel' to go back to the main menu.");
            String tempCode = userInput();

            while(!tempCode.equals(server.TOTPcode(user.secretCode))) //Add counter. Max 5 tries.
            {
                if (tempCode.equals("cancel")) break;
                System.out.println("Code incorrect. Please try again.");
                tempCode = userInput();
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

        System.out.println("Confirm password: ");

        while(!firstPass.equals(s.nextLine()))
        {
            System.out.println("\nPasswords do not match.\n\nPlease enter your password.");
            firstPass = userInput();
            System.out.println("Confirm password: ");
        }

        server.receivedRegistration(tempName, firstPass);
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