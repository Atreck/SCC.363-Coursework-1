import java.rmi.*;

public interface MedicalService extends Remote
{
    public void testMethod(String user, String pass) throws Exception;
}