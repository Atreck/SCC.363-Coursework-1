package main;

import javax.crypto.SealedObject;
import java.io.Serializable;

public class SafeMessage implements Serializable {

    private SealedObject obj;
    private byte[] secretKeyEncrypted;

    public SafeMessage(SealedObject obj, byte[] secretKeyEncrypted) {
        this.obj = obj;
        this.secretKeyEncrypted = secretKeyEncrypted;
    }

    public SealedObject getObj() {
        return obj;
    }

    public byte[] getSecretKeyEncrypted() {
        return secretKeyEncrypted;
    }
}
