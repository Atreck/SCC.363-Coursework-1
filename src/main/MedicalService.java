package main;

import encryption.CryptUtil;
import signatures.SignUtil;

import javax.crypto.SealedObject;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.rmi.*;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public interface MedicalService extends Remote {
    
    //TODO: Add docs and comments.

    SafeMessage authenticateUser(SafeMessage obj) throws Exception;

    void logout(SafeMessage obj) throws Exception;

    SafeMessage getRecords(SafeMessage obj) throws Exception;

    SafeMessage updateRecords(SafeMessage obj) throws Exception;

    int verifyPassword(String username, String password) throws Exception;

    SafeMessage verifyCode(SafeMessage obj) throws Exception;

    int addPatient(Message message) throws Exception;

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

    default void register(String user) throws Exception {
        System.out.println("User created with username: " + user);
        // Generate a key pair for the newly added user
        CryptUtil.genKeyPair(CryptUtil.ALGO_NAME, user);
    }

    String secretKeyGen() throws Exception;
    
    void lockUser(String user) throws Exception;
}