package supercool363;

import java.io.Serializable;

public class User implements Serializable
{
    // TODO: Add docs and comments.

    private String username;
    private String password;
    private int tries = 3;
    private byte[] salt;
    private String secretCode;

    public User(String user, String pass, String code, byte[] saltCode) {
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

    public String getUsername() {
        return username;
    }

    public String getPassword() {
        return password;
    }

    public byte[] getSalt() {
        return salt;
    }

    public String getSecretCode() {
        return secretCode;
    }

    public int getTries() {
        return tries;
    }

    public void setTries(int tries) {
        this.tries = tries;
    }
}
