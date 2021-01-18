import java.rmi.Naming;

public class Server extends java.rmi.server.UnicastRemoteObject implements MedicalService {

    public Server() throws Exception
    {
        super();
    }

    public void testMethod(String user, String pass)
    {
        System.out.println("SUCCESS WITH USER " + user + " AND PASSWORD " + pass);
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
