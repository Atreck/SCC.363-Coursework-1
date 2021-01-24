import java.rmi.Naming;
import java.security.*;
import java.util.HashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.codec.binary.*;
import de.taimos.totp.*;

public class Server extends java.rmi.server.UnicastRemoteObject implements MedicalService
{
    //TODO: Add docs and comments.

    private static HashMap<String, User> database = new HashMap<>();
    private String tempUsername;

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

    public boolean userExists(String user) throws Exception
    {
        return database.containsKey(user);
    }

    public Message validateUsername(Message request) throws Exception {
        tempUsername = null;
        tempUsername = request.getUsername();
        boolean valid = !userExists(tempUsername);
        System.out.println(valid);
        return new Message(valid);
    }

    public Message validatePassword(Message request) throws Exception {
        String password = request.getPassword();
        boolean valid = strengthCheck(password);
        if (valid) {
            // ready to be stored
            String saltedPass = saltPass(password);
            // ready to be stored
            register(tempUsername, password);
        }
        else { System.out.println("Registration failed with username:" + tempUsername +
                "and password: " + password);}
        return new Message(valid);
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

    public void lockUser(String user) throws Exception
    {
        // Okay this is just so beautiful, can we leave it like that please hahahah ~ Kas
        System.out.println("SKIDADDLE SKIDOODLE THE USER " + user + " IS NOW A NOODLE");
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
