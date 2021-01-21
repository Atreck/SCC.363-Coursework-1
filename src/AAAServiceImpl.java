import javax.rmi.ssl.SslRMIClientSocketFactory;
import javax.rmi.ssl.SslRMIServerSocketFactory;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;

public class AAAServiceImpl extends java.rmi.server.UnicastRemoteObject implements AAAService {

    private static final int PORT = 2019;

    public AAAServiceImpl() throws Exception
    {
        super(PORT, new RMISSLClientSocketFactory(),
                new RMISSLServerSocketFactory());
        startService();
    }

    private void startService() {
//        // Create and install a security manager
//        if (System.getSecurityManager() == null) {
//            System.setSecurityManager(new SecurityManager());
//        }

        try {
            // Create SSL-based registry
            Registry registry = LocateRegistry.createRegistry(PORT,
                    new RMISSLClientSocketFactory(),
                    new RMISSLServerSocketFactory());

            // Bind this object instance to the name "AAAServer"
            registry.bind("AAAServer", this);

            System.out.println("AAAServer bound in registry\nServer running...");
        } catch (Exception e) {
            System.out.println("AAAServer implementation err: " + e.getMessage());
            e.printStackTrace();
        }
    }

    public String sayHello() {
        return "Hello World!";
    }

    public void testMethod(String user, String pass)
    {
        System.out.println("SUCCESS WITH USER " + user + " AND PASSWORD " + pass);
    }

    public static void main(String[] args) throws Exception
    {
        AAAServiceImpl aaaService = new AAAServiceImpl();
    }
}
