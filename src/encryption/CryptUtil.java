package encryption;

import main.Message;

import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SealedObject;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
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

    public static final String ALGO_TYPE = "SHA256WithRSA";  //Maybe change it to SHA256withRSA later (slower but more robust)
    public static final String ALGO_NAME = "RSA";

    /**
     * A method enabling the storage of keys in files.
     * @param path path to the location of a key
     * @param key a key in byte[] format
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
     * TODO: update the docs
     * Helper method for decoding a private key from a base64 encoded String
     * into a PrivateKey java object.
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


    public SealedObject encrypt(Message obj, PublicKey publicKey)
            throws IllegalBlockSizeException, InvalidKeyException, NoSuchAlgorithmException,
            NoSuchPaddingException, InvalidKeySpecException, IOException
    {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-1AndMGF1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        SealedObject sealedObject = new SealedObject(obj, cipher);

        return sealedObject;
    }

    public Message decrypt(SealedObject object, PrivateKey privateKey)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException,
            IOException, ClassNotFoundException, InvalidKeySpecException
    {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-1AndMGF1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        Message decrypted = (Message) object.getObject(privateKey);
        return decrypted;
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
}
