package org.ccipstest.app;


import java.security.SecureRandom;
import java.util.Arrays;

import static org.ccipstest.app.Algs.AUTHKEYLENGTH;
import static org.ccipstest.app.Algs.ENCKEYLENGTH;

public class CryptoConfig {
    private Algs.EncAlgType encAlg;
    private Algs.AuthAlgType intAlg;
    private long encKeyLength;
    private long authKeyLength;
    private byte[] encKey;
    private byte[] intKey;
    private byte[] iv;
    private SecureRandom secureRandom = new SecureRandom();
    //private final ReadWriteLock lock = new ReentrantReadWriteLock();

    public CryptoConfig(Algs.EncAlgType encAlg, Algs.AuthAlgType intAlg) {
        this.encAlg = encAlg;
        this.intAlg = intAlg;
        this.encKeyLength = ENCKEYLENGTH.get(encAlg);
        this.authKeyLength = AUTHKEYLENGTH.getOrDefault(intAlg,0L);
        this.encKey = null;
        this.intKey = null;
        this.iv = null;
    }

    public void setNewCryptoValues(){
        encKey = new byte[(int) this.encKeyLength];
        secureRandom.nextBytes(encKey);

        intKey = new byte[(int) authKeyLength];
        secureRandom.nextBytes(intKey);

        iv = new byte[(int) encKeyLength];
        secureRandom.nextBytes(iv);
    }


    public Algs.EncAlgType getEncAlg() {
        return this.encAlg;
    }
    public Algs.AuthAlgType getIntAlg() {
        return intAlg;
    }
    public long getEncKeyLength() {
        return this.encKeyLength;
    }
    public long getAuthKeyLength() {
        return this.authKeyLength;
    }
    public byte[] getEncKey() {
        return this.encKey;
    }
    public byte[] getIntKey() {
        return this.intKey;
    }
    public byte[] getIv() {
        return this.iv;
    }
    public void setIv(byte[] iv) {
        this.iv = iv;
    }

    @Override
    public String toString() {
        return "CryptoConfig{" +
                "encAlg=" + encAlg +
                ", intAlg=" + intAlg +
                ", encKeyLength=" + encKeyLength +
                ", authKeyLength=" + authKeyLength +
                ", encKey=" + Arrays.toString(encKey) +
                ", intKey=" + Arrays.toString(intKey) +
                ", iv=" + Arrays.toString(iv) +
                ", secureRandom=" + secureRandom +
                '}';
    }
}