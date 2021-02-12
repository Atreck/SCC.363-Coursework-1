package main;

import de.taimos.totp.TOTP;
import encryption.CryptUtil;
import org.apache.commons.codec.binary.Base32;
import org.apache.commons.codec.binary.Hex;
import org.json.simple.*;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import javax.imageio.IIOException;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;

public class RecordsUtil {

    private static final int LOCKED = 8;
    private static final int CREDENTIALS_BAD = 3;
    private static final int PASS_OK = 1;
    private static final int TRIES = 3;
    private static final int CODE_INCORRECT = 4;
    private static final int CODE_CORRECT = 5;

    public static final long CAN_REGISTER_ACCOUNTS = 1;
    public static final long CAN_DELETE_ACCOUNTS = 2;
    public static final long CAN_ASSIGN_PERMS = 3;
    public static final long CAN_REVOKE_PERMS = 4;
    public static final long CAN_READ_PATIENTS = 5;
    public static final long CAN_WRITE_PATIENTS = 6;
    public static final long CAN_UPDATE_PATIENTS_CONTACT = 7;
    public static final long CAN_REGISTER_PATIENTS = 8;
    public static final long CAN_CHANGE_USER_PASS = 9;
    public static final long CAN_UPDATE_OWN_CONTACT = 11;
    public static final long CAN_READ_LOGS = 12;
    public static final long CAN_READ_USERS = 13;
    public static final long CAN_WRITE_USERS = 14;
    public static final long CAN_CREATE_GROUPS = 15;
    public static final long CAN_DEL_GROUPS = 16;
    public static final long CAN_READ_GROUPS = 17;
    public static final long CAN_WRITE_GROUPS = 18;


    // ------------------ TIMEOUT ------------------//
    // timeout in milliseconds
    //current timestamp - last_accessed >= timeout ----> log out a user
    // 5 minutes
    private static final long TIMEOUT = 300000;            // 5 mins

    // --------------- VS CODE PATH PREFIX ------------//
    private static String prefix = ".";
    // --------------- INTELLIJ PATH PREFIX ----------//
//    private static String prefix = "src";

    public static boolean hasPerms(String username, Long perms) throws IOException, ParseException {
        Context context = getContext(username);
        if (context.getPermissions().contains(perms)) return true;
        return false;
    }

    public static void assignToGroup(String assignee, String group) throws IOException, ParseException {
        String path = prefix +"/Users/users.json";
        Object obj1 = new JSONParser().parse(new FileReader(path));
        JSONObject jo1 = (JSONObject) obj1;

        jo1.put(assignee, group);

        PrintWriter pw = new PrintWriter(path);
        pw.write(jo1.toJSONString());

        pw.flush();
        pw.close();
    }

    public static String readPatient(String username) throws IOException, ParseException {
        // check to which group the user belongs to
        String group = getGroup(username);

        // typecasting obj to JSONObject
        JSONObject jo = getUserJObj(username, group);

        jo.put("last_active", System.currentTimeMillis());
        updateUserJobj(username, group, jo);

        String records = (String) jo.get("records");
        return records;
    }

    // dummy function just to update the last_active timestamp
    public static void updateUserTimestamp(String username) throws IOException, ParseException {
        String group = getGroup(username);

        // typecasting obj to JSONObject
        JSONObject jo = getUserJObj(username, group);

        jo.put("last_active", System.currentTimeMillis());
        updateUserJobj(username, group, jo);
    }

    public static Map<String, String> readUsers() throws IOException, ParseException {
        Object obj1 = new JSONParser().parse(new FileReader(prefix +"/Users/users.json"));
        JSONObject jo = (JSONObject) obj1;
        Map<String, String> users = new HashMap<>();

        JSONArray usernames = (JSONArray) jo.get("usernames");
        Iterator iter = usernames.iterator();

        while (iter.hasNext()) {
            String username = (String) iter.next();
            users.put(username, (String) jo.get(username));
        }

        return users;
    }

    public static HashSet<Long> readGroupPerms(String group) throws IOException, ParseException {
        Object obj = new JSONParser().parse(new FileReader(prefix+"/Users/permissions.json"));
        JSONObject jo = (JSONObject) obj;

        JSONArray ja = (JSONArray) jo.get(group);

        HashSet<Long> permissions = new HashSet<>();
        // iterating through permissions
        Iterator itr2 = ja.iterator();
        while (itr2.hasNext())
        {
            long permission = (long) itr2.next();
            permissions.add(permission);
//            System.out.println(permission);
        }

        return permissions;
    }

    public static void setGroupPerms(HashSet<Long> permissions, String group) throws IOException, ParseException {
        String path = prefix+"/Users/permissions.json";
        Object obj = new JSONParser().parse(new FileReader(path));
//        System.out.println("Setting new permissions..");
        JSONObject jo = (JSONObject) obj;

        JSONArray ja = (JSONArray) jo.get(group);
        for (Long l: permissions) ja.add(l);

        jo.put(group, ja);

        PrintWriter pw = new PrintWriter(path);
        pw.write(jo.toJSONString());

        pw.flush();
        pw.close();

    }

    private static String getGroup(String username) throws IOException, ParseException {
        Object obj1 = new JSONParser().parse(new FileReader(prefix +"/Users/users.json"));
        JSONObject jo1 = (JSONObject) obj1;
        // check to which group the user belongs to
        String group = (String) jo1.get(username);

        return group;
    }

    private static JSONObject getUserJObj(String username, String group) throws IOException, ParseException {
        String path = String.format(prefix+"/Users/%s/%s.json", group, username);

        Object obj2 = new JSONParser().parse(new FileReader(path));
        // typecasting obj to JSONObject
        JSONObject jo2 = (JSONObject) obj2;

        return jo2;
    }

    private static void updateUserJobj(String username, String group, JSONObject obj) throws FileNotFoundException {
        String path = String.format(prefix+"/Users/%s/%s.json", group, username);

        PrintWriter pw = new PrintWriter(path);
        pw.write(obj.toJSONString());

        pw.flush();
        pw.close();
    }

    public static Context getContext(String username) throws IOException, ParseException {

        String group = getGroup(username);

        // now check permissions associated with that group
        Object obj = new JSONParser().parse(new FileReader(prefix+"/Users/permissions.json"));
        JSONObject jo = (JSONObject) obj;

        // typecasting obj to JSONObject
        JSONObject jo2 = getUserJObj(username, group);
        long active = (long) jo2.get("active");
        long locked = (long) jo2.get("locked");

        HashSet<Long> permissions = readGroupPerms(group);
        return new Context(group, active, locked, permissions);
    }

    public static void login(String username) throws IOException, ParseException {
        String group = getGroup(username);

        // typecasting obj to JSONObject
        JSONObject jo = getUserJObj(username, group);

        // active indicates whether a user has been authenticated, etc and logged in successfully or exited the system
        // 0 - inactive
        // 1 - active
        jo.put("active", 1);
        // add a timestamp
        jo.put("last_active", System.currentTimeMillis());
        updateUserJobj(username, group, jo);
    }

    public static void logout(String username) throws IOException, ParseException {
        String group = getGroup(username);

        JSONObject jo = getUserJObj(username, group);

        jo.put("active", 0);

    }

    public static void blockUser(String username) throws IOException, ParseException {
        String group = getGroup(username);
        JSONObject obj = getUserJObj(username, group);

        obj.put("locked", 1);
        updateUserJobj(username, group, obj);
    }

    public static void unblockUser(String username) throws IOException, ParseException {
        String group = getGroup(username);
        JSONObject obj = getUserJObj(username, group);

        obj.put("locked", 0);
        updateUserJobj(username, group, obj);
    }

    public static boolean userExists(String username) throws IOException, ParseException {
        Object obj = new JSONParser().parse(new FileReader(prefix+"/Users/users.json"));

        // typecasting obj to JSONObject
        JSONObject jo = (JSONObject) obj;
        JSONArray users = (JSONArray) jo.get("usernames");

        if (users.contains(username)) return true;
        return false;
    }

    public static boolean inactiveTimeout(String username) throws IOException, ParseException {
        String group = getGroup(username);
        JSONObject obj = getUserJObj(username, group);

        long lastActive = (long) obj.get("last_active");

        if (System.currentTimeMillis() - lastActive >= TIMEOUT) {
            obj.put("active", 0);
            updateUserJobj(username, group, obj);
            return true;
        } return false;
    }

    public static int passMatches(String username, String providedPass) throws Exception {

        String group = getGroup(username);

        // typecasting obj to JSONObject
        JSONObject jo = (getUserJObj(username, group));

        String correctHash = (String) jo.get("passHash");
        String salt = (String) jo.get("salt");

        // needs to use longs not sure why (maybe ints are not serializable or smth?)
        long tries = (long) jo.get("tries");

        String thisHash = CryptUtil.saltPass(providedPass, salt);

        if (thisHash.equals(correctHash)) {
            jo.put("tries", TRIES);     // reset tries
            updateUserJobj(username, group, jo);
            return PASS_OK;
        }
        else {
            tries -= 1;
            jo.put("tries", tries);
            updateUserJobj(username, group, jo);
            if (tries == 0) return LOCKED;
            else return CREDENTIALS_BAD;
        }
    }

    public static int codeMatches(String username, String providedCode) throws Exception {
        String group = getGroup(username);
        JSONObject jo = getUserJObj(username, group);

        String correctCode = (String) jo.get("authKey");
        String code = "";
        if (correctCode.equals("none")) {
            code = correctCode;
        } else {
            code = TOTPcode(correctCode);
        }

        // needs to use longs not sure why (maybe ints are not serializable or smth?)
        long tries = (long) jo.get("tries");

        if (providedCode.equals(code)) {
            jo.put("tries", TRIES);     // reset tries
            updateUserJobj(username, group, jo);
            return CODE_CORRECT;
        }
        else {
            tries -= 1;
            jo.put("tries", tries);
            updateUserJobj(username, group, jo);
            if (tries == 0) return LOCKED;
            else return CODE_INCORRECT;
        }
    }

    public static String TOTPcode(String secretKey) throws Exception {
        byte[] bytes = new Base32().decode(secretKey);
        String hexKey = Hex.encodeHexString(bytes);
        return TOTP.getOTP(hexKey);
    }

    public static void addPatient(
            String username, String name, String surname, String email,
            String password, String code)
            throws Exception {

        String salt = CryptUtil.genSalt().toString();
        String saltedPass = CryptUtil.saltPass(password, salt);

        JSONObject jo = new JSONObject();

        jo.put("name", name);
        jo.put("surname", surname);
        jo.put("email", email);
        jo.put("summary", "None");
        jo.put("records", "None");
        jo.put("prescriptions", "None");
        jo.put("passHash", saltedPass);
        jo.put("salt", salt);
        jo.put("authKey", code);
        jo.put("tries", 3);
        jo.put("active", 0);
        jo.put("last_active", 0);
        jo.put("locked", 0);

        PrintWriter pw = new PrintWriter(String.format(prefix+"/Users/Patients/%s.json", username));
        pw.write(jo.toJSONString());
        pw.flush();
        pw.close();

        // add to user -> group mapping file
        Object obj = new JSONParser().parse(new FileReader(prefix+"/Users/users.json"));
        // typecasting obj to JSONObject
        JSONObject jo2 = (JSONObject) obj;
        PrintWriter pw2 = new PrintWriter(prefix+"/Users/users.json");
        JSONArray users = (JSONArray) jo2.get("usernames");
        users.add(username);
        jo2.put("usernames", users);
        jo2.put(username, "Patients");
        pw2.write(jo2.toJSONString());
        pw2.flush();
        pw2.close();
    }

    public static void addUser(String name, String surname, String username, String email,
                               String password, String group, String code)  throws  Exception {

        String salt = CryptUtil.genSalt().toString();
        String saltedPass = CryptUtil.saltPass(password, salt);

        JSONObject jo = new JSONObject();

        jo.put("name", name);
        jo.put("surname", surname);
        jo.put("email", email);
        jo.put("passHash", saltedPass);
        jo.put("salt", salt);
        jo.put("authKey", code);
        jo.put("tries", 3);
        jo.put("active", 0);
        jo.put("last_active", 0);
        jo.put("locked", 0);

        PrintWriter pw = new PrintWriter(String.format(prefix+"/Users/%s/%s.json", group, username));
        pw.write(jo.toJSONString());
        pw.flush();
        pw.close();

        // add to user -> group mapping file
        Object obj = new JSONParser().parse(new FileReader(prefix+"/Users/users.json"));
        // typecasting obj to JSONObject
        JSONObject jo2 = (JSONObject) obj;
        PrintWriter pw2 = new PrintWriter(prefix+"/Users/users.json");
        jo2.put(username, group);
        JSONArray users = (JSONArray) jo2.get("usernames");
        users.add(username);
        jo2.put("usernames", users);
        pw2.write(jo2.toJSONString());
        pw2.flush();
        pw2.close();
    }

    public static void main(String[] args) throws Exception {

//        // creating JSONObject
//        JSONObject jo = new JSONObject();
//
//        // putting data to JSONObject
//        jo.put("firstName", "John");
//        jo.put("lastName", "Doe");
//        jo.put("email", "jdoe@email.com");
//        jo.put("age", 26);
//
//        // for address data, first create LinkedHashMap
//        Map m = new LinkedHashMap(4);
//        m.put("streetAddress", "21 Broadway Street");
//        m.put("city", "New York");
//        m.put("state", "NY");
//        m.put("postalCode", 10021);
//
//        jo.put("address", m);
//
//        Map r = new LinkedHashMap(2);
//        r.put("summary", "Patient is stupid and probs has the lowest IQ on earth.");
//        r.put("prescriptions", "Start reading books mate.");
//        jo.put("records", r);
//
//        // writing JSON to file
//        PrintWriter pw = new PrintWriter("src/Users/128/JohnDoe.json");
//        pw.write(jo.toJSONString());
//
//        pw.flush();
//        pw.close();

        //----------------------------------------------------------------------------------//
        //--------------------------- Read from JSON ---------------------------------------//
        // parsing file "JSONExample.json"
//        Object obj = new JSONParser().parse(new FileReader("src/Users/users.json"));
//
//        JSONObject ja = (JSONObject) obj;
//
//        Iterator iter = ja.iterator();
//
//        while(iter.hasNext()) {
//            System.out.println(iter.next());
//        }
//
//        // typecasting obj to JSONObject
//        JSONObject jo = (JSONObject) obj;
//
//        // getting firstName and lastName
//        String firstName = (String) jo.get("firstName");
//        String lastName = (String) jo.get("lastName");
//
//        System.out.println(firstName);

//        jo.put("firstName", "Jessica");
//        PrintWriter pw = new PrintWriter("src/Users/Patients/JohnDoe.json");
//        pw.write(jo.toJSONString());
//        pw.flush();
//        pw.close();
//
//        System.out.println((String) jo.get("firstName"));
    }
}
