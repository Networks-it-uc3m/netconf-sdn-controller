package org.ccips.app.handler;

import org.onosproject.netconf.NetconfController;
import org.onosproject.netconf.NetconfSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;


public class StorageHandler {
    public static Map<Long, Handler> storage = new HashMap<>();
    private static final Logger log = LoggerFactory.getLogger(StorageHandler.class);
    private static final Object lock = new Object();
    private static final Random random = new Random();
    public static NetconfController controller;


    public static long generateUniqueRandomKey() {
        synchronized (lock) {
            long key;
            do {
                key = random.nextInt(10000) & 0xFFFFFFFFL;
            } while (storage.containsKey(key));
            return key;
        }
    }

    public static Handler createHandler(request request, NetconfSession newDeviceSession_1, NetconfSession newDeviceSession_2) throws Exception {
        synchronized (lock) {
            long req_id = generateUniqueRandomKey();
            Handler h;
            try {
            h = Handler.newHandler(request, req_id, newDeviceSession_1, newDeviceSession_2);
                log.info("Handler created");
            if (h == null) {
                throw new Exception("Error creating handler");
            }

            if (!h.setInitialConfigValues(newDeviceSession_1, newDeviceSession_2)) {
                throw new Exception("Error setting initial config values");
            }
            log.info("Initial values have been established");
            log.info("Handler assigned to id {}", req_id);
            storage.put(req_id, h);
            log.info("Handler {} stored", req_id);
            } catch (Exception e) {
                log.error("Exception occurred while creating handler: {}", e.getMessage());
                throw e;
            }
            return h;
        }
    }

    public static void rekey(String name_spi) throws Exception {
        synchronized (lock) {
            try {
                String[] s = name_spi.split("_");
                String name = s[0];
                long spi = Long.parseLong(s[1]);
                Long reqId = findHandlerKeyContaining(name);
                if (reqId == null) {
                    throw new Exception(String.format("Handler with id %s, does not exist", name));
                }
                if (!storage.get(reqId).processRekey(controller, name, spi)) {
                    throw new Exception("Error rekeying handler");
                }
            } catch (Exception e) {
                log.error("Exception occurred while rekeying: {}", e.getMessage());
                throw e;
            }
        }
    }

    public static void deleteHandler(String reqId) throws Exception {
        Long reqId_aux;
        synchronized (lock) {
            try {
                Handler handler;
                reqId_aux = Long.parseLong(reqId);
                handler = storage.get(reqId_aux);
                if (handler == null) {
                    throw new Exception(String.format("Handler with id %s does not exist", reqId));
                }

                handler.delete();
                storage.remove(reqId_aux);
            } catch (Exception e) {
                log.error("Exception occurred while deleting handler: {}", e.getMessage());
                throw e;
            }
        }
    }

    public static Long findHandlerKeyContaining(String key) {

        for (Map.Entry<Long, Handler> entry : storage.entrySet()) {
            if (entry.getValue().keyExists(key)) {
                return entry.getKey();
            }
        }
        return null;
    }

}




