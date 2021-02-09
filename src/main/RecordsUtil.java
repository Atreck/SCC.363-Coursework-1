package main;

import de.taimos.totp.TOTP;
import encryption.CryptUtil;
import org.apache.commons.codec.binary.Base32;
import org.apache.commons.codec.binary.Hex;
import org.json.simple.*;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.HashSet;
import java.util.Iterator;

public class RecordsUtil {

    private static final int LOCKED = 8;
    private static final int CREDENTIALS_BAD = 3;
    private static final int PASS_OK = 1;
    private static final int TRIES = 3;
    private static final int CODE_INCORRECT = 4;
    private static final int CODE_CORRECT = 5;

    private static final int CAN_REGISTER_ACCOUNTS = 1;
    private static final int CAN_DELETE_ACCOUNTS = 2;
    private static final int CAN_ASSIGN_PERMS = 3;
    private static final int CAN_REVOKE_PERMS = 4;
    private static final int CAN_READ_PATIENTS = 5;
    private static final int CAN_WRITE_PATIENTS = 6;
    private static final int CAN_UPDATE_PATIENTS_CONTACT = 7;
    private static final int CAN_REGISTER_PATIENTS = 8;
    private static final int CAN_CHANGE_USER_PASS = 9;
    private static final int CAN_READ_OWN_RECORD = 10;
    private static final int CAN_UPDATE_OWN_CONTACT = 11;
    private static final int CAN_READ_LOGS = 12;


    public static boolean hasReadPatientsPermission(String username) throws IOException, ParseException {
        Context context = getContext(username);
        if (context.getPermissions().contains(CAN_READ_PATIENTS)) return true;
        return false;
    }

    public static String readPatient(String username) throws IOException, ParseException {
        Object obj1 = new JSONParser().parse(new FileReader("src/Users/users.json"));
        JSONObject jo1 = (JSONObject) obj1;
        // check to which group the user belongs to
        String group = (String) jo1.get(username);

        // based on the group go into the correct user dir and file
        Object obj = new JSONParser().parse(new FileReader(String.format("src/Users/%s/%s.json", group, username)));

        // typecasting obj to JSONObject
        JSONObject jo = (JSONObject) obj;

        String records = (String) jo.get("records");
        return records;
    }

    public static boolean isActive(String username) throws IOException, ParseException {
        Object obj1 = new JSONParser().parse(new FileReader("src/Users/users.json"));
        JSONObject jo1 = (JSONObject) obj1;
        // check to which group the user belongs to
        String group = (String) jo1.get(username);

        // based on the group go into the correct user dir and file
        Object obj = new JSONParser().parse(new FileReader(String.format("src/Users/%s/%s.json", group, username)));

        // typecasting obj to JSONObject
        JSONObject jo = (JSONObject) obj;

        // read the value of active: 0 - inactive, 1 - active)
        long active = (long) jo.get("active");
        if (active == 0) return false;
        else if (active == 1) return true;
        else return false;
    }

    public static Context getContext(String username) throws IOException, ParseException {
        Object obj1 = new JSONParser().parse(new FileReader("src/Users/users.json"));
        JSONObject jo1 = (JSONObject) obj1;
        String group = (String) jo1.get(username);

        // now check permissions associated with that group
        Object obj = new JSONParser().parse(new FileReader("src/Users/permissions.json"));
        JSONObject jo = (JSONObject) obj;

        // get the active and locked flags
        Object obj2 = new JSONParser().parse(new FileReader(String.format("src/Users/%s/%s.json", group, username)));

        // typecasting obj to JSONObject
        JSONObject jo2 = (JSONObject) obj;

        long active = (long) jo.get("active");
        long locked = (long) jo.get("locked");

        HashSet<Long> permissions = new HashSet<>();

        JSONArray ja = (JSONArray) jo.get(group);

        // iterating phoneNumbers
        Iterator itr2 = ja.iterator();

        while (itr2.hasNext())
        {
            long permission = (long) itr2.next();
            permissions.add(permission);
        }

        return new Context(group, active, locked, permissions);
    }

    public static void login(String username) throws IOException, ParseException {
        Object obj1 = new JSONParser().parse(new FileReader("src/Users/users.json"));
        JSONObject jo1 = (JSONObject) obj1;
        String group = (String) jo1.get(username);
        Object obj = new JSONParser().parse(new FileReader(String.format("src/Users/%s/%s.json", group, username)));

        // typecasting obj to JSONObject
        JSONObject jo = (JSONObject) obj;

        // active indicates whether a user has been authenticated, etc and logged in successfully or exited the sytem
        // 0 - inactive
        // 1 - active
        jo.put("active", 1);
        PrintWriter pw = new PrintWriter(String.format("src/Users/%s/%s.json", group, username));
        pw.write(jo.toJSONString());

        pw.flush();
        pw.close();
    }

    public static void logout(String username) throws IOException, ParseException {
        Object obj1 = new JSONParser().parse(new FileReader("src/Users/users.json"));
        JSONObject jo1 = (JSONObject) obj1;
        String group = (String) jo1.get(username);
        Object obj = new JSONParser().parse(new FileReader(String.format("src/Users/%s/%s.json", group, username)));

        // typecasting obj to JSONObject
        JSONObject jo = (JSONObject) obj;

        jo.put("active", 0);
        PrintWriter pw = new PrintWriter(String.format("src/Users/%s/%s.json", group, username));
        pw.write(jo.toJSONString());

        pw.flush();
        pw.close();
    }

    public static boolean userExists(String username) throws IOException, ParseException {
        Object obj = new JSONParser().parse(new FileReader("src/Users/users.json"));

        // typecasting obj to JSONObject
        JSONObject jo = (JSONObject) obj;

        String user = (String) jo.get(username);
        if (user != null) return true;
        return false;
    }

    public static int passMatches(String username, String providedPass) throws Exception {
        Object obj1 = new JSONParser().parse(new FileReader("src/Users/users.json"));
        JSONObject jo1 = (JSONObject) obj1;
        String group = (String) jo1.get(username);
        Object obj = new JSONParser().parse(new FileReader(String.format("src/Users/%s/%s.json", group, username)));

        // typecasting obj to JSONObject
        JSONObject jo = (JSONObject) obj;

        String correctHash = (String) jo.get("passHash");
        String salt = (String) jo.get("salt");

        // needs to use longs not sure why (maybe ints are not serializable or smth?)
        long tries = (long) jo.get("tries");

        String thisHash = CryptUtil.saltPass(providedPass, salt);

        if (thisHash.equals(correctHash)) {
            jo.put("tries", TRIES);     // reset tries
            PrintWriter pw = new PrintWriter(String.format("src/Users/%s/%s.json", group, username));
            pw.write(jo.toJSONString());

            pw.flush();
            pw.close();
            return PASS_OK;
        }
        else {
            tries -= 1;
            jo.put("tries", tries);
            PrintWriter pw = new PrintWriter(String.format("src/Users/%s/%s.json", group, username));
            pw.write(jo.toJSONString());

            pw.flush();
            pw.close();
            if (tries == 0) return LOCKED;
            else return CREDENTIALS_BAD;
        }
    }

    public static int codeMatches(String username, String providedCode) throws Exception {
        Object obj1 = new JSONParser().parse(new FileReader("src/Users/users.json"));
        JSONObject jo1 = (JSONObject) obj1;
        String group = (String) jo1.get(username);
        Object obj = new JSONParser().parse(new FileReader(String.format("src/Users/%s/%s.json", group, username)));

        // typecasting obj to JSONObject
        JSONObject jo = (JSONObject) obj;

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
            PrintWriter pw = new PrintWriter(String.format("src/Users/%s/%s.json", group, username));
            pw.write(jo.toJSONString());

            pw.flush();
            pw.close();
            return CODE_CORRECT;
        }
        else {
            tries -= 1;
            jo.put("tries", tries);
            PrintWriter pw = new PrintWriter(String.format("src/Users/%s/%s.json", group, username));
            pw.write(jo.toJSONString());

            pw.flush();
            pw.close();
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

        PrintWriter pw = new PrintWriter(String.format("src/Users/Patients/%s.json", username));
        pw.write(jo.toJSONString());
        pw.flush();
        pw.close();

        // add to user -> group mapping file
        Object obj = new JSONParser().parse(new FileReader("src/Users/users.json"));
        // typecasting obj to JSONObject
        JSONObject jo2 = (JSONObject) obj;
        PrintWriter pw2 = new PrintWriter("src/Users/users.json");
        jo2.put(username, "Patients");
        pw2.write(jo2.toJSONString());
        pw2.flush();
        pw2.close();
    }


    public static void addAdmin(
            String username, String name, String surname, String email,
            String password, String code)
            throws Exception {

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

        PrintWriter pw = new PrintWriter(String.format("src/Users/Admins/%s.json", username));
        pw.write(jo.toJSONString());
        pw.flush();
        pw.close();

        // add to user -> group mapping file
        Object obj = new JSONParser().parse(new FileReader("src/Users/users.json"));
        // typecasting obj to JSONObject
        JSONObject jo2 = (JSONObject) obj;
        PrintWriter pw2 = new PrintWriter("src/Users/users.json");
        jo2.put(username, "Admins");
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
//        Object obj = new JSONParser().parse(new FileReader("src/Users/Patients/JohnDoe.json"));
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

        // For simplicity
//        int uniqueID = Math.abs("kacha546".hashCode());
//        String id = String.valueOf(uniqueID);
//        String fullId = ADMIN_PREFIX + id;
//        fullId = fullId.substring(3);
//        System.out.print(fullId);
    }
}
