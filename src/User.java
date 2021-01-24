import java.io.Serializable;

public class User implements Serializable
{
    // TODO: Add docs and comments.

    public String username;
    public String password;
    public byte[] salt;
    public String secretCode;

    public User(String user, String pass, String code, byte[] saltCode)
    {
        this.username = user;
        this.password = pass;
        this.secretCode = code;
        this.salt = saltCode;
    }

    // Added a second constructor to ignore the code errors in the Server.java for now..
    public User(String user, String pass, String code) {
        this.username = user;
        this.password = pass;
        this.secretCode = code;
    }
}
