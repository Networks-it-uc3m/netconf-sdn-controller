package org.ccipstest.app;

public class SPIManager {
    private static long cSPI=0;
    public static synchronized long getNewSPI() {
            cSPI++;
            return cSPI;
    }
}