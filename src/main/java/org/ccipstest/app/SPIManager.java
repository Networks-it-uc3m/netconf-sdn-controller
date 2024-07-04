package org.ccipstest.app;

import java.util.concurrent.locks.ReentrantReadWriteLock;

public class SPIManager {
    private static long cSPI=0; // Current SPI number
    private static final ReentrantReadWriteLock lock = new ReentrantReadWriteLock();


    // Method to get a new SPI
    public static long getNewSPI() {
        lock.writeLock().lock();
        try {
            cSPI++;
            return cSPI;

        } finally {
            lock.writeLock().unlock();
        }
    }



    // Getter for current SPI
    public long getCurrentSPI() {
        lock.readLock().lock();
        try {
            return cSPI;
        } finally {
            lock.readLock().unlock();
        }
    }

    // Setter for current SPI (optional, depending on your needs)

}