import java.rmi.*;

public interface AAAService extends Remote
{
    void testMethod(String user, String pass) throws Exception;
    String sayHello() throws Exception;
}