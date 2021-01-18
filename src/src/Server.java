import java.rmi.Naming;

public class Server extends java.rmi.server.UnicastRemoteObject {

    public Server() throws Exception {
        super();
        connectToRMI();
        connectToRMI();
    }
    public void connectToRMI() throws Exception {
        try {
            System.out.println("Starting the server...");
            // Binds an auction to a specified endpoint
            Naming.rebind("rmi://localhost/MedicalService", this);
            System.out.println("Server running at rmi://localhost/MedicalService");
        }
        catch(Exception e) {
            System.out.println("Server error: " + e);
        }
    }

    public static void main(String[] args) {
        try {
            new Server();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
