package encryption;

import main.Message;
import org.apache.commons.codec.digest.Crypt;

import javax.crypto.*;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * A simple utility aiding the creation of public and private key pairs.
 *
 * NOTE: Normally there is some authority assigning the keys,
 * it wouldn't look like this in the production - this is just a
 * simplified version to aid the development process.
 */

public class CryptUtil {

    public static final String ALGO_TYPE = "SHA256WithRSA";
    public static final String ALGO_NAME = "RSA";

    /**
     * A method enabling the storage of keys in files.
     *
     * @param path path to the location of a key
     * @param key  a key in byte[] format
     */
    private static void saveInFile(String path, byte[] key) {
        File file = new File(path);
        file.getParentFile().mkdirs();
        try {
            FileOutputStream fileOutputStream = new FileOutputStream(file);
            fileOutputStream.write(key);
            fileOutputStream.flush();
            fileOutputStream.close();
        } catch (IOException e) {
            System.out.println(e);
        }
    }

    /**
     * Generates a pair of public and private keys.
     * Saved in a dedicated folder based on a client username - can be used by a server later.
     * For the client - the pair is stored directly in their associated object.
     *
     * @param algo algorithm to be used for instantiating the KeyPairGenerator, e.g. "RSA", "DSA"
     * @param user name of the user for which this keyPair is going to be generated
     * @return the generated KeyPair consisting of a public and a private key
     * @throws NoSuchAlgorithmException
     */
    public static KeyPair genKeyPair(String algo, String user) throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(algo);
        SecureRandom secureRandom = new SecureRandom();
        keyGen.initialize(2048, secureRandom);
        // Keys can be 1024 or 2048-bit long (the longer the harder to crack)
        KeyPair pair = keyGen.generateKeyPair();

        saveInFile("src/Keys/" + user + "/PublicKey", pair.getPublic().getEncoded());
        saveInFile("src/Keys/" + user + "/PrivateKey", pair.getPrivate().getEncoded());

        return pair;
    }

    /**
     * Helper function generating a secret key - meant for symmetric encryption.
     * @return secret key
     * @throws Exception
     */
    public static SecretKey genSecretKey() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        SecureRandom secureRandom = new SecureRandom();
        keyGenerator.init(128, secureRandom);

        SecretKey secret = keyGenerator.generateKey();

        return secret;
    }

    /**
     * TODO: update the docs
     * Helper method for decoding a private key from a base64 encoded String
     * into a PrivateKey java object.
     *
     * @param algo algorithm on which the key is based (DSA/ RSA)
     * @return a PrivateKey instance based on paramas provided
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    public static PrivateKey getPrivateKey(String algo, String username)
            throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {

        // -------------------- FOR VS CODE ---------------------------------
//        String path = String.format("Keys/%s/PrivateKey", username);
        // -------------------- FOR INTELLIJ --------------------------------
        String path = String.format("src/Keys/%s/PrivateKey", username);
        FileInputStream fis = new FileInputStream(path);
        byte[] privateKey = fis.readAllBytes();

        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKey);
        KeyFactory keyFactory = KeyFactory.getInstance(algo);
        PrivateKey privKey = keyFactory.generatePrivate(keySpec);

        return privKey;
    }

    /**
     * Helper method for decoding a public key from a base64 encoded String
     * into a PublicKey java object.
     *
     * @param algo algorithm on which the key is based (DSA/ RSA)
     * @return a PublicKey instance based on paramas provided
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    public static PublicKey getPublicKey(String algo, String username) throws NoSuchAlgorithmException,
            InvalidKeySpecException, IOException {

        // -------------------- FOR VS CODE ---------------------------------
//        String path = String.format("Keys/%s/PublicKey", username);
        // -------------------- FOR INTELLIJ --------------------------------
        String path = String.format("src/Keys/%s/PublicKey", username);

        FileInputStream fis = new FileInputStream(path);
        byte[] pubKey = fis.readAllBytes();

        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(pubKey);
        KeyFactory keyFactory = KeyFactory.getInstance(algo);
        PublicKey publicKey = keyFactory.generatePublic(keySpec);

        return publicKey;
    }


    /**
     * Helper function to encrypt data being exchanged between a client and the server.
     * Data is assumed to be an instance of the Message object.
     *
     * @param obj       Message to encrypted
     * @param secretKey a secret key generated by an entity sending a message
     * @return an encrypted obj - instance of SealedObject
     * @throws IllegalBlockSizeException
     * @throws InvalidKeyException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     * @throws InvalidKeySpecException
     * @throws IOException
     */
    public static SealedObject encrypt(Message obj, SecretKey secretKey)
            throws IllegalBlockSizeException, InvalidKeyException, NoSuchAlgorithmException,
            NoSuchPaddingException, InvalidKeySpecException, IOException {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);

        SealedObject sealedObject = new SealedObject(obj, cipher);

        return sealedObject;
    }

    /**
     * Helper function to encrypt data being exchanged between a client and the server.
     * Data is assumed to be an instance of the Message object.
     *
     * @param secretKey to be encrypted by an entity sending a message
     * @param publicKey public key of an entity to which the message is sent
     * @return an encrypted obj - instance of SealedObject
     * @throws IllegalBlockSizeException
     * @throws InvalidKeyException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     * @throws InvalidKeySpecException
     * @throws IOException
     */
    public static byte[] encrypt(SecretKey secretKey, PublicKey publicKey)
            throws IllegalBlockSizeException, InvalidKeyException, NoSuchAlgorithmException,
            NoSuchPaddingException, InvalidKeySpecException, IOException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-1AndMGF1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        byte[] secretEncrypted = cipher.doFinal(secretKey.getEncoded());

        return secretEncrypted;
    }

    /**
     * A helper function to decrypt an ecnrypted Message sent between a client
     * and a server.
     *
     * @param object    an encrypted Message instance
     * @param secretKey secretKey decrypted by an entity for which the message was intended
     * @return a decrypted instance of Message object
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws IOException
     * @throws ClassNotFoundException
     * @throws InvalidKeySpecException
     */
    public static Message decrypt(SealedObject object, SecretKey secretKey)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException,
            IOException, ClassNotFoundException {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        Message decrypted = (Message) object.getObject(secretKey);
        return decrypted;
    }

    /**
     * A helper function to decrypt an ecnrypted Message sent between a client
     * and a server.
     *
     * @param secretEncrypted encrypted secret key, can only be decrepted with a private key of an entity
     *                        for which the message was intended
     * @param privateKey      private key of the receiver, an entity for which the message was intended
     * @return a decrypted instance of Message object
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws IOException
     * @throws ClassNotFoundException
     * @throws InvalidKeySpecException
     */
    public static SecretKey decrypt(byte[] secretEncrypted, PrivateKey privateKey)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException,
            IOException, ClassNotFoundException, InvalidKeySpecException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-1AndMGF1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decrypted = cipher.doFinal(secretEncrypted);
        SecretKey secretKey = new SecretKeySpec(decrypted, "AES");
        return secretKey;
    }



    public static String saltPass(String pass, String salt) throws Exception {
        // https://www.baeldung.com/java-password-hashing

        byte[] byteSalt = salt.getBytes();

        KeySpec spec = new PBEKeySpec(pass.toCharArray(), byteSalt, 65536, 128);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");

        byte[] hashed = factory.generateSecret(spec).getEncoded();

        StringBuilder stringBuilder = new StringBuilder();
        for (byte b : hashed)
            stringBuilder.append(String.format("%02x", b));

        String encodedPassword = stringBuilder.toString();

        return encodedPassword;
    }


    public static byte[] genSalt() {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[16];
        random.nextBytes(salt);

        return salt;
    }




        /* Comment and uncomment depending on the need
        (should be a one-time use only for creating the server's key pair)
   */
//    public static void main (String[] args) {
//        try {
//            CryptUtil.genKeyPair(ALGO_NAME, "server");
//        } catch (NoSuchAlgorithmException e) {
//            e.printStackTrace();
//        }
//    }


//        public static void main (String[] args) {
//        try {
////            CryptUtil.genSecretKey();
//            SecretKey key = getSecretKey();
//
//            System.out.println(Base64.getEncoder().encodeToString(key.getEncoded()));
//
//            byte[] encrypted = CryptUtil.encrypt(key, CryptUtil.getPublicKey(CryptUtil.ALGO_NAME, "server"));
//            System.out.println(Base64.getEncoder().encodeToString(encrypted));
//
//
//            SecretKey key1 = CryptUtil.decrypt(encrypted, CryptUtil.getPrivateKey(CryptUtil.ALGO_NAME, "server"));
//            System.out.println(Base64.getEncoder().encodeToString(key1.getEncoded()));
//
//            assert(key1 == key);
//
//
//        } catch (NoSuchAlgorithmException e) {
//            e.printStackTrace();
//        } catch (Exception e) {
//            e.printStackTrace();
//        }
//    }
//}


//    public static void main(String[] args) {
//        try {
//            SecretKey key = CryptUtil.genSecretKey();
//            Message message = new Message(4);
//            SealedObject obj = CryptUtil.encrypt(message, key);
//
//            byte[] encrypted = CryptUtil.encrypt(key, CryptUtil.getPublicKey(CryptUtil.ALGO_NAME, "server"));
//            SecretKey key1 = CryptUtil.decrypt(encrypted, CryptUtil.getPrivateKey(CryptUtil.ALGO_NAME, "server"));
//
//            Message message1 = CryptUtil.decrypt(obj, key1);
//
//            assert message1 == message;
//
//        } catch (NoSuchAlgorithmException e) {
//            e.printStackTrace();
//        } catch (Exception e) {
//            e.printStackTrace();
//        }
//    }
}

