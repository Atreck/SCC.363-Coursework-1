package main;

import java.io.Serializable;

public class Message implements Serializable {

    /**
     * Simple class encapsulating the information sent by a client.
     * Can later be further encapsulated with the SealedObject to make the
     * traffic encrypted.
     */

    private String username;
    private String password;
    private String code;
    private boolean valid;
    private User user;
    private Frontend client;
    private int status;
    private int tries;

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

    public Message(String username, String password, Frontend client) {
        this.username = username;
        this.password = password;
        this.client = client;
    }

    public Message(String username, String password, String code) {
        this.username = username;
        this.password = password;
        this.code = code;
    }

    public Message(boolean valid) { this.valid = valid; }

    public Message(User user) { this.user = user; }

    public Message(int status) { this.status = status; }

    public Message(int status, int tries) {
        this.status = status;
        this.tries = tries;
    }

    public Message(int status, User user) {
        this.status = status;
        this.user = user;
    }

    /**
     * Obtains a username connected with this request.
     * @return username provided with this request
     */
    public String getUsername() {return username; }

    /**
     * Obtains a User instance supplied with this message.
     * @return User object
     */
    public User getUser() { return user; }

    /**
     * obtains a password supplied with this request
     * @return a password associated with this request
     */
    public String getPassword() { return password; }

    /**
     * Indicator of whether a username/ password was successfully
     * validated by server.
     * @return true if (usually, but can be sth else) username/ password valid,
     * false otherwise
     */
    public boolean isValid() {
        return valid;
    }

    public Frontend getClient() {
        return client;
    }

    public int getStatus() {
        return status;
    }

    public int getTries() {
        return tries;
    }

    public String getCode() {
        return code;
    }
}
