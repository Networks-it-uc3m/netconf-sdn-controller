package org.ccips.app.security;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

public class CertificateStore {
    public static final Map<UUID, String> certs = new HashMap<>();

    public static synchronized UUID storeCertificate(String cert) {
        UUID certID = UUID.randomUUID();
        certs.put(certID, cert);
        return certID;
    }

    public static synchronized String getCertificate(UUID certID) {
        return certs.get(certID);
    }
}
