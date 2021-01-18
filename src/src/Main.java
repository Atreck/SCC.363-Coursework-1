import java.rmi.*;
import java.util.*;

public class Main
{
    private static Scanner s = new Scanner(System.in);
    private static HashMap<String, String> database = new HashMap<>();
    private static MedicalService server;
    private static String tempName;
    private static String firstPass;
    public static void main(String[] args) throws Exception
    {
        try {
            server = (MedicalService) Naming.lookup("rmi://localhost/MedicalService");

            database.put("admin", "password");

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
    
            server.testMethod(tempName, firstPass);
            System.out.println("User added.");
        } catch (Exception e) {
            System.out.println("Server exception: " + e);
        }
    }
}