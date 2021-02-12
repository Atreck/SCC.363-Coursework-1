package main;

import java.io.Serializable;

import javax.crypto.SealedObject;

public class SafeMessage implements Serializable {

    private static final long serialVersionUID = 1L;
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
