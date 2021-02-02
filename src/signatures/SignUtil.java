package signatures;

import encryption.CryptUtil;

import java.io.*;
import java.security.*;

import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

/**
 * A simple utility aiding the creation of signature which can be used later for verifying the
 *  users by a server and vice-versa.
 *
 */

public class SignUtil {

//    /**
//     * Obtains a key pair of public and private keys from
//     * corresponding files for a specified user.
//     * @param user a user whose key pair is to be obtained
//     * @param algo an algorithm which the keys are based on (DSA/RSA, in this case DSA)
//     * @return a key pair consisting of a public and a private key
//     * @throws IOException
//     * @throws InvalidKeySpecException
//     * @throws NoSuchAlgorithmException
//     */
//    public static KeyPair retrieveKeys(String user, String algo)
//            throws IOException, InvalidKeySpecException, NoSuchAlgorithmException {
//
//        // Find the path of the key pair for a user
//
//// -------------------- FOR VS CODE ---------------------------------
//        String path1 = String.format("Keys/%s/PrivateKey", user);
//        String path2 = String.format("Keys/%s/PublicKey", user);
//// -------------------- FOR INTELLIJ --------------------------------
////        String path1 = String.format("src/Keys/%s/PrivateKey", user);
////        String path2 = String.format("src/Keys/%s/PublicKey", user);
//        // Read the files --> in bytes format
//        FileInputStream fis = new FileInputStream(path1);
//        FileInputStream fis2 = new FileInputStream(path2);
//        byte[] privateKey = fis.readAllBytes();
//        byte[] publicKey = fis2.readAllBytes();
//        // Finally decode bytes to a String
//        String privKey = Base64.getEncoder().encodeToString(privateKey);
//        String pubKey = Base64.getEncoder().encodeToString(publicKey);
//
//        // Generate keys from their corresponding Strings based on the algorithm they were created with
//        KeyPair pair = new KeyPair(getPublicKey(pubKey, algo), getPrivateKey(privKey, algo));
//
//        return pair;
//    }

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
        Signature signature = Signature.getInstance(CryptUtil.ALGO_TYPE);
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
        Signature signature = Signature.getInstance(CryptUtil.ALGO_TYPE);
        signature.initVerify(pubKey);
        signature.update(challenge.getBytes("UTF8"));
        boolean verified = signature.verify(Base64.getDecoder().decode(signedChallenge));

        return verified;
    }
}
