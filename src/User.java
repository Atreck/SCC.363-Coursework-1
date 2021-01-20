import java.io.Serializable;

public class User implements Serializable
{
    public String username;
    public String password;
    public String secretCode;

    public User(String user, String pass, String code)
    {
        this.username = user;
        this.password = pass;
        this.secretCode = code;
    }
}
