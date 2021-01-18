import java.rmi.Naming;

public class Client {

    private MedicalService medicalService;

    public Client() throws Exception {
        System.out.println("Starting the MedicalService CLI for a client...");
        this.medicalService = (MedicalService) Naming.lookup("rmi://localhost/MedicalService");
    }

    public static void main(String[] args) {
        try {
            new Client();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
