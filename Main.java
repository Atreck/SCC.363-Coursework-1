import java.util.*;

public class Main
{
    private Scanner s = new Scanner(System.in);
    private HashMap<String, String> database = new HashMap<>();
    String tempName;
    String firstPass;

    public Main()
    {
        database.put("admin", "password");
        register();
    }

    public void register()
    {
        System.out.println("REGISTRATION SYSTEM\n\nEnter username: ");
        tempName = s.nextLine();

        while(database.containsKey(tempName))
        {
            System.out.println("\nUsername is already taken.\n\nPlease enter a new username: ");
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

        database.put(tempName, firstPass);
        System.out.println("User added.");
    }
    public static void main(String[] args)
    {
        new Main();
    }
}