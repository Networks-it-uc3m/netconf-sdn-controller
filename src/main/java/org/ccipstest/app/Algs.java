package org.ccipstest.app;

import java.util.HashMap ;
import java.util.Map ;

public class Algs {

    public enum EncAlgType {
        DESCBC(2),
        TRIPLEDESCBC(3),
        CASTCBC(6),
        BLOWFISHCBC(7),
        AESCBC(12),
        AESCTR(13),
        AESCCMV8(14),
        AESCCMV12(15),
        AESCCMV16(16),
        AESGCMV8(18),
        AESGCMV12(19),
        AESGCMV16(20);

        private final int value;

        EncAlgType(int value) {
            this.value = value;
        }

        public int getValue() {
            return value;
        }
    }

    public enum AuthAlgType {
        MD5(2),
        SHA1(3),
        SHA2_256(5),
        SHA2_384(6),
        SHA2_512(7),
        RIPEMD160(8),
        AES_XCBC_MAC(9);

        private final int value;

        AuthAlgType(int value) {
            this.value = value;
        }

        public int getValue() {
            return value;
        }
    }

    public static final Map<String, EncAlgType> ENCALGS = new HashMap<String, EncAlgType>() {{
        put("des-cbc", EncAlgType.DESCBC);
        put("3-des-cbc", EncAlgType.TRIPLEDESCBC);
        put("cast-cbc", EncAlgType.CASTCBC);
        put("blowfish-cbc", EncAlgType.BLOWFISHCBC);
        put("aes-cbc", EncAlgType.AESCBC);
        put("aes-ctr", EncAlgType.AESCTR);
        put("aes-ccmv-8", EncAlgType.AESCCMV8);
        put("aes-ccmv-12", EncAlgType.AESCCMV12);
        put("aes-ccmv-16", EncAlgType.AESCCMV16);
        put("aes-gcmv-8", EncAlgType.AESGCMV8);
        put("aes-gcmv-12", EncAlgType.AESGCMV12);
        put("aes-gcmv-16", EncAlgType.AESGCMV16);
    }};

    public static final Map<EncAlgType, Long> ENCKEYLENGTH = new HashMap<EncAlgType, Long>() {{
        put(EncAlgType.DESCBC, 8L);
        put(EncAlgType.TRIPLEDESCBC, 16L);
        put(EncAlgType.CASTCBC, 16L);
        put(EncAlgType.BLOWFISHCBC, 24L);
        put(EncAlgType.AESCBC, 32L);
        put(EncAlgType.AESCTR, 64L);
        put(EncAlgType.AESCCMV8, 32L);
        put(EncAlgType.AESCCMV12, 48L);
        put(EncAlgType.AESCCMV16, 64L);
        put(EncAlgType.AESGCMV8, 32L);
        put(EncAlgType.AESGCMV12, 48L);
        put(EncAlgType.AESGCMV16, 64L);
    }};

    public static final Map<AuthAlgType, Long> AUTHKEYLENGTH = new HashMap<AuthAlgType, Long>() {{
        put(AuthAlgType.MD5, 16L);
        put(AuthAlgType.SHA1, 10L);
        put(AuthAlgType.SHA2_256, 32L);
        put(AuthAlgType.SHA2_384, 48L);
        put(AuthAlgType.SHA2_512, 64L);
        put(AuthAlgType.RIPEMD160, 20L);
        put(AuthAlgType.AES_XCBC_MAC, 16L);
    }};

    public static final Map<String, AuthAlgType> AUTHALGS = new HashMap<String, AuthAlgType>() {
        {
            put("md5", AuthAlgType.MD5);
            put("sha1", AuthAlgType.SHA1);
            put("sha2-256", AuthAlgType.SHA2_256);
            put("sha2-384", AuthAlgType.SHA2_384);
            put("sha2-512", AuthAlgType.SHA2_512);
            put("ripemd-160", AuthAlgType.RIPEMD160);
            put("aes-cbc-mac", AuthAlgType.AES_XCBC_MAC);
        }
    };
}

