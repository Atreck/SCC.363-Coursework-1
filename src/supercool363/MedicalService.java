package supercool363;

import signatures.SignatureUtil;
import java.nio.charset.StandardCharsets;
import java.rmi.*;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public interface MedicalService extends Remote {
    
    //TODO: Add docs and comments.

    Message authenticateUser(Message message) throws Exception;

    Message verifyPassword(Message message) throws Exception;

    Message verifyCode(Message message) throws Exception;

    void addUser(Message message) throws Exception;
    
    void createQRimage(Message m) throws Exception;

    Message validateUsername(Message message) throws Exception;

    Message validatePassword(Message message) throws Exception;

    default boolean strengthCheck(String input) throws Exception {
        Pattern p = Pattern.compile("[^A-Za-z0-9 ]"); // Find character not in that list
        Matcher m = p.matcher(input);

        if (m.find()) // If a special character is found
        {
            p = Pattern.compile("[0-9]");
            m = p.matcher(input);

            if (m.find()) {
                p = Pattern.compile("[A-Z]");
                m = p.matcher(input);

                if (m.find()) {
                    p = Pattern.compile("[a-z]");
                    m = p.matcher(input);

                    if ((m.find()) && (input.length() > 10)) return true;
                }

            }
        }
        return false;
    }

    default void register(String user, String pass) throws Exception {
        System.out.println("User created with username: " + user + " and password: " + pass);
        // Generate a key pair for the newly added user
        SignatureUtil.genKeyPair(SignatureUtil.ALGO_NAME, user);
    }

    default String saltPass(String pass) throws Exception {
        MessageDigest digest;

        try {
            digest = MessageDigest.getInstance("SHA-256");
        } catch (Exception e) {
            //TODO: handle exception
            return null;
        }

        SecureRandom random = new SecureRandom();

        byte[] salt = new byte[16];
        random.nextBytes(salt);

        digest.update(salt);

        byte[] hashed = digest.digest(pass.getBytes(StandardCharsets.UTF_8));

        StringBuilder stringBuilder = new StringBuilder();
        for (byte b : hashed)
            stringBuilder.append(String.format("%02x", b));

        String encodedPassword = stringBuilder.toString();

        return encodedPassword;
    }

    String secretKeyGen() throws Exception;

    String TOTPcode(String secretKey) throws Exception;
    
    void lockUser(String user) throws Exception;
}