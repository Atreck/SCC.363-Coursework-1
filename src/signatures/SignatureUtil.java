package signatures;

import java.io.*;
import java.security.*;

import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * A simple utility aiding the creation of public and private key pairs
 * as well as the signature which can be used later for verifying the
 *  users by a server and vice-versa.
 *
 *  NOTE: Normally there is some authority assigning the keys,
 *  it wouldn't look like this in the production - this is just a
 *  simplified version to aid the development process.
 */

public class SignatureUtil {

    private static final String ALGO_TYPE = "SHA256WithDSA";  //Maybe change it to SHA256withRSA later (slower but more robust)
    public static final String ALGO_NAME = "DSA";

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

        saveInFile("../Keys/" + user + "/PublicKey", pair.getPublic().getEncoded());
        saveInFile("../Keys/" + user + "/PrivateKey", pair.getPrivate().getEncoded());

        return pair;
    }

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
     * Obtains a key pair of public and private keys from
     * corresponding files for a specified user.
     * @param user a user whose key pair is to be obtained
     * @param algo an algorithm which the keys are based on (DSA/RSA, in this case DSA)
     * @return a key pair consisting of a public and a private key
     * @throws IOException
     * @throws InvalidKeySpecException
     * @throws NoSuchAlgorithmException
     */
    public static KeyPair retrieveKeys(String user, String algo)
            throws IOException, InvalidKeySpecException, NoSuchAlgorithmException {

        // Find the path of the key pair for a user
        String path1 = String.format("src/Keys/%s/PrivateKey", user);
        String path2 = String.format("src/Keys/%s/PublicKey", user);
        // Read the files --> in bytes format
        FileInputStream fis = new FileInputStream(path1);
        FileInputStream fis2 = new FileInputStream(path2);
        byte[] privateKey = fis.readAllBytes();
        byte[] publicKey = fis2.readAllBytes();
        // Finally decode bytes to a String
        String privKey = Base64.getEncoder().encodeToString(privateKey);
        String pubKey = Base64.getEncoder().encodeToString(publicKey);

        // Generate keys from their corresponding Strings based on the algorithm they were created with
        KeyPair pair = new KeyPair(getPublicKey(pubKey, algo), getPrivateKey(privKey, algo));

        return pair;
    }

    /**
     * Helper method for decoding a private key from a base64 encoded String
     * into a PrivateKey java object.
     * @param base64PrivateKey a String containing the key
     * @param algo algorithm on which the key is based (DSA/ RSA)
     * @return a PrivateKey instance based on paramas provided
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    private static PrivateKey getPrivateKey(String base64PrivateKey, String algo)
            throws NoSuchAlgorithmException, InvalidKeySpecException {

        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(base64PrivateKey.getBytes()));
        KeyFactory keyFactory = KeyFactory.getInstance(algo);
        PrivateKey privateKey = keyFactory.generatePrivate(keySpec);

        return privateKey;
    }

    /**
     * Helper method for decoding a public key from a base64 encoded String
     * into a PublicKey java object.
     * @param base64PublicKey a String containing the key
     * @param algo algorithm on which the key is based (DSA/ RSA)
     * @return a PublicKey instance based on paramas provided
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    private static PublicKey getPublicKey(String base64PublicKey, String algo) throws NoSuchAlgorithmException, InvalidKeySpecException {

        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(base64PublicKey.getBytes()));
        KeyFactory keyFactory = KeyFactory.getInstance(algo);
        PublicKey publicKey = keyFactory.generatePublic(keySpec);

        return publicKey;
    }

    /**
     * Method which allows to sign a challenge sent by some verification party.
     * @param challenge a challenge sent by the other party
     * @param privKey a PrivateKey of the party receiving the challenge
     * @return a signed challenge
     * @throws NoSuchAlgorithmException
     * @throws IOException
     * @throws InvalidKeySpecException
     * @throws InvalidKeyException
     * @throws SignatureException
     */
    public static String signChallenge(String challenge, PrivateKey privKey)
            throws NoSuchAlgorithmException, IOException, InvalidKeySpecException,
            InvalidKeyException, SignatureException
    {
        Signature signature = Signature.getInstance(ALGO_TYPE);
        signature.initSign(privKey);
        signature.update(challenge.getBytes("UTF8"));

        byte[] signatureBytes = signature.sign();
        return Base64.getEncoder().encodeToString(signatureBytes);
    }

    /**
     * Verifies whether a challenge signed by the party to which the challenge was sent
     * corresponds to the challenge sent by a verification party.
     * @param signedChallenge a signed challenge by the party to be verified
     * @param challenge an original challenge with no signatures
     * @param pubKey public key of a party to which challenge was sent
     * @return true if the challenge was successfully verified, false otherwise
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws UnsupportedEncodingException
     * @throws SignatureException
     */
    public static boolean verifyChallenge(String signedChallenge, String challenge, PublicKey pubKey)
            throws NoSuchAlgorithmException, InvalidKeyException,
            UnsupportedEncodingException, SignatureException {
        Signature signature = Signature.getInstance(ALGO_TYPE);
        signature.initVerify(pubKey);
        signature.update(challenge.getBytes("UTF8"));
        boolean verified = signature.verify(Base64.getDecoder().decode(signedChallenge));

        return verified;
    }


    /* Comment and uncomment depending on the need
        (should be a one-time use only for creating the server's key pair)
   */
    public static void main (String[] args) {
        try {
            SignatureUtil.genKeyPair(ALGO_NAME, "server");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }
}
