package org.ccips.app.config;

public class SPIManager {
    private static long cSPI=0;
    public static synchronized long getNewSPI() {
            cSPI++;
            return cSPI;
    }
}