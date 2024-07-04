package org.ccipstest.app;

import org.onosproject.mastership.MastershipService;
import org.onosproject.netconf.NetconfController;
import org.onosproject.netconf.NetconfSession;

import java.util.HashMap;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.locks.ReentrantReadWriteLock;

public class StorageHandler {
    public static Map<Long, Handler> storage = new HashMap<>();
    private static final ReentrantReadWriteLock lock = new ReentrantReadWriteLock();
    private static final Random random = new Random();
    static long key=0;
    public static NetconfController controller;
    public static MastershipService mastershipService;


    public static long generateUniqueRandomKey() {

        do {
            key++;
        } while (storage.containsKey(key)||key<0||key>100);
        return key;
    }

    // Create a new Handler and store it
    public static void createHandler(request request, NetconfSession newDeviceSession_1, NetconfSession newDeviceSession_2) throws Exception {
        long req_id = generateUniqueRandomKey();

        Handler h = Handler.newHandler(request,req_id,newDeviceSession_1,newDeviceSession_2);
        System.out.println("Handler created");
        if (h == null) {
            throw new Exception("Error creating handler");
        }

        // This will mean that most probably the handler has established the session with the Netconf server
        if (!h.setInitialConfigValues(newDeviceSession_1,newDeviceSession_2)) {
            throw new Exception("Error setting initial config values");
        }
        System.out.println("Initial values have been established");
        System.out.printf("Handler assigned to id %s%n", req_id);

        lock.writeLock().lock();
        try {
            storage.put(req_id, h);
            System.out.printf("Handler %s stored%n", req_id);
        } finally {
            lock.writeLock().unlock();
        }


    }

    // Delete a Handler by its UUID
    public static void deleteHandler(long id) throws Exception {
        lock.writeLock().lock();
        try {
            Handler handler = storage.get(id);
            if (handler == null) {
                throw new Exception(String.format("Handler with id %s, does not exist", id));
            }

            if (!handler.stop()) {
                throw new Exception("Error stopping handler");
            } else {
                storage.remove(id);
            }
        } finally {
            lock.writeLock().unlock();
        }
    }

    public static void rekey(String name_spi) throws Exception {
        lock.writeLock().lock();
        try {
            String[] s = name_spi.split("_");
            if (s.length < 2) {
                throw new Exception("The id of the SAD notification is incorrect");
            }
            String name=s[0];
            long spi = Long.parseLong(s[1]);
            Long reqId= findHandlerKeyContaining(name);
            if (reqId==null) {
                throw new Exception(String.format("Handler with id %s, does not exist", name));
            }
            if (!storage.get(reqId).processRekey(controller,mastershipService,name ,spi)) {
                throw new Exception("Error rekeying handler");
            }


        } finally {
            lock.writeLock().unlock();
        }
    }




    public static Long findHandlerKeyContaining(String key) {
        lock.readLock().lock();
        try {
            for (Map.Entry<Long, Handler> entry : storage.entrySet()) {
                if (entry.getValue().keyExists(key)) {
                    return entry.getKey();
                }
            }
            return null;
        } finally {
            lock.readLock().unlock();
        }
    }
}




