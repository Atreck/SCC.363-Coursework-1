import java.rmi.*;

public interface MedicalService extends Remote
{
    public User retrieveUser(String username) throws Exception;

    public void addUser(String username, String password, String key) throws Exception;

    public Boolean userExists(String user) throws Exception;

    public void receivedRegistration(String user, String pass) throws Exception;

    public String secretKeyGen() throws Exception;

	public String TOTPcode(String secretKey) throws Exception;
}