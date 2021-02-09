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
    private String name;
    private String surname;
    private String email;
    private String code;
    private String records;
    private String group;
    private boolean valid;
    private Main client;
    private int status;

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

    public Message(String username, String password, Main client) {
        this.username = username;
        this.password = password;
        this.client = client;
    }

    public Message(String username, String password, String code) {
        this.username = username;
        this.password = password;
        this.code = code;
    }

    public Message(String name, String surname, String username, String password, String email,String code) {
        this.name = name;
        this.surname = surname;
        this.username = username;
        this.password = password;
        this.email = email;
        this.code = code;
    }

    public Message(boolean valid) { this.valid = valid; }

    public Message(int status) { this.status = status; }

    public Message(int status, String group) {
        this.status = status;
        this.group = group;
    }

    /**
     * Obtains a username connected with this request.
     * @return username provided with this request
     */
    public String getUsername() {return username; }

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

    public Main getClient() {
        return client;
    }

    public int getStatus() {
        return status;
    }

    public String getCode() {
        return code;
    }

    public String getName() {
        return name;
    }

    public String getSurname() {
        return surname;
    }

    public String getEmail() {
        return email;
    }

    public String getGroup() {
        return group;
    }
}
