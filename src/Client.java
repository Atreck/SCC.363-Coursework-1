import java.net.InetAddress;
import java.rmi.Naming;
import javax.rmi.ssl.SslRMIClientSocketFactory;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;

public class Client {

    private AAAService AAAServiceObj;

    private final int PORT = 2019;

    public Client() {
        connectClient();
    }

    private void connectClient() {
        try {
            // Make reference to SSL-based registry
//            System.out.println(InetAddress.getLocalHost().getHostName());
            Registry registry = LocateRegistry.getRegistry(
                    InetAddress.getLocalHost().getHostName(), PORT,
                    new RMISSLClientSocketFactory());

            // "obj" is the identifier that we'll use to refer
            // to the remote object that implements the "Hello"
            // interface
            this.AAAServiceObj = (AAAService) registry.lookup("AAAServer");

            String message = "blank";
            message = this.AAAServiceObj.sayHello();
            System.out.println(message+"\n");
        } catch (Exception e) {
            System.out.println("HelloClient exception: " + e.getMessage());
            e.printStackTrace();
        }
    }

    public static void main(String args[]) {
       Client client = new Client();
    }
}
