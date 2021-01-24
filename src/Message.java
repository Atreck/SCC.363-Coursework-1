import java.io.Serializable;

public class Message implements Serializable {

    /**
     * Simple class encapsulating the information sent by a client.
     * Can later be further encapsulated with the SealedObject to make the
     * traffic encrypted.
     */

    private String username;
    private String password;
    private boolean valid;

    /**
     * Constructs a client request containing a client's (prospect)
     * password and a (prospect) username - probably for a server to verify/ validate.
     * Note: Either username or password can be null, but not both.
     * @param username client's username
     * @param password client's password
     */
    public Message(String username, String password) {
        this.username = username;
        this.password = password;
    }

    public Message(boolean valid) { this.valid = valid; }

    /**
     * Obtains a username connected with this request.
     * @return username provided with this request
     */
    public String getUsername() {return username;}

    /**
     * obtains a password supplied with this request
     * @return a password associated with this request
     */
    public String getPassword() { return password;}

    /**
     * Indicator of whether a username/ password was successfully
     * validated by server.
     * @return true if (usually, but can be sth else) username/ password valid,
     * false otherwise
     */
    public boolean isValid() {
        return valid;
    }
}
