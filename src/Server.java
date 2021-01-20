import java.rmi.Naming;
import java.security.*;
import java.util.HashMap;

import org.apache.commons.codec.binary.*;
import de.taimos.totp.*;

public class Server extends java.rmi.server.UnicastRemoteObject implements MedicalService
{
    //TODO: Add docs and comments.

    private static HashMap<String, User> database = new HashMap<>();

    public Server() throws Exception
    {
        super();
        addUser("admin", "password", "BGLBEVX44CZC45IOAQI3IFJBDBEOYY3A");
    }

    public User retrieveUser(String username) throws Exception
    {
        return database.get(username);
    }

    public void addUser(String username, String password, String key) throws Exception
    {
        database.put(username, new User(username, password, key));
    }

    public Boolean userExists(String user) throws Exception
    {
        return database.containsKey(user);
    }

    public void receivedRegistration(String user, String pass) throws Exception
    {
        System.out.println("User created with username: " + user + " and password: " + pass);
    }

    public String secretKeyGen() throws Exception
	{
		byte[] bytes = new byte[20];
		new SecureRandom().nextBytes(bytes);
    	return new Base32().encodeToString(bytes);
	}

	public String TOTPcode(String secretKey) throws Exception
	{
    	byte[] bytes = new Base32().decode(secretKey);
		String hexKey = Hex.encodeHexString(bytes);
		return TOTP.getOTP(hexKey);
    }
    public static void main(String[] args) throws Exception
    {
        try {
            System.out.println("Starting the server...");
            MedicalService server = new Server();
            Naming.rebind("rmi://localhost/MedicalService", server);
            System.out.println("Server running at rmi://localhost/MedicalService");
        } catch(Exception e) {
            System.out.println("Server error: " + e);
        }
    }
}
