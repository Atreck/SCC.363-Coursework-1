import com.google.zxing.oned.rss.expanded.decoders.AbstractExpandedDecoder;
import signatures.SignUtil;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.rmi.*;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public interface MedicalService extends Remote {
    
    //TODO: Add docs and comments.

    Message authenticateUser(Message message) throws Exception;

    int verifyPassword(String username, String password) throws Exception;

    Message verifyCode(Message message) throws Exception;

    void addUser(Message message) throws Exception;
    
    void createQRimage(Message m) throws Exception;

    boolean validateUsername(String username) throws Exception;

    Message validateUsername(Message message) throws Exception;

    Message validatePassword(Message message) throws Exception;

    boolean challengeUser(Main client, String username) throws Exception;

    String signChallenge(String challenge) throws Exception;

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

                    if ((m.find()) && (input.length() > 9)) return true;
                }

            }
        }
        return false;
    }

    default void register(String user, String pass) throws Exception {
        System.out.println("User created with username: " + user + " and password: " + pass);
        // Generate a key pair for the newly added user
        SignUtil.genKeyPair(SignUtil.ALGO_NAME, user);
    }

    default String saltPass(String pass) throws Exception {
        // https://www.baeldung.com/java-password-hashing

        SecureRandom random = new SecureRandom();

        byte[] salt = new byte[16];
        random.nextBytes(salt);

        KeySpec spec = new PBEKeySpec(pass.toCharArray(), salt, 65536, 128);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");

        byte[] hashed = factory.generateSecret(spec).getEncoded();

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