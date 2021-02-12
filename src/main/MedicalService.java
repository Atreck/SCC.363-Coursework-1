package main;

import java.rmi.Remote;

public interface MedicalService extends Remote {
    
    //TODO: Add docs and comments.

    SafeMessage authenticateUser(SafeMessage obj) throws Exception;

    void logout(SafeMessage obj) throws Exception;

    SafeMessage getRecords(SafeMessage obj) throws Exception;

    SafeMessage getUsers(SafeMessage obj) throws Exception;

    SafeMessage getGroupPerms(SafeMessage obj) throws Exception;

    SafeMessage setGroupPerms(SafeMessage obj) throws Exception;

    SafeMessage assignToGroup(SafeMessage obj) throws Exception;

    SafeMessage addUser(SafeMessage obj) throws Exception;

    SafeMessage updateRecords(SafeMessage obj) throws Exception;

    int verifyPassword(String username, String password) throws Exception;

    SafeMessage verifyCode(SafeMessage obj) throws Exception;

    boolean delUser(String user, String issuer, String reason) throws Exception;

    int addPatient1(Message message) throws Exception;

    SafeMessage addPatient2(SafeMessage obj) throws Exception;

    boolean challengeUser(Main client, String username) throws Exception;

    String signChallenge(String challenge) throws Exception;

    boolean strengthCheck(String input) throws Exception;

    boolean strengthCheck(Message m) throws Exception;

    void register(String user) throws Exception;

    String secretKeyGen() throws Exception;
    
    void lockUser(String user) throws Exception;
}