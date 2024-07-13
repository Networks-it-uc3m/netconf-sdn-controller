package org.ccipstest.app;


import org.onosproject.mastership.MastershipService;
import org.onosproject.netconf.NetconfController;
import org.onosproject.netconf.NetconfSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.locks.ReentrantReadWriteLock;

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

    // Create a new Handler and store it
    public static void createHandler(request request, NetconfSession newDeviceSession_1, NetconfSession newDeviceSession_2) throws Exception {
        synchronized (lock) {
            long req_id = generateUniqueRandomKey();
            try {
            Handler h = Handler.newHandler(request, req_id, newDeviceSession_1, newDeviceSession_2);
            System.out.println("Handler created");
            if (h == null) {
                throw new Exception("Error creating handler");
            }

            if (!h.setInitialConfigValues(newDeviceSession_1, newDeviceSession_2)) {
                throw new Exception("Error setting initial config values");
            }
            System.out.println("Initial values have been established");
            System.out.printf("Handler assigned to id %s%n", req_id);



                storage.put(req_id, h);
                System.out.printf("Handler %s stored%n", req_id);
            } catch (Exception e) {
                log.error("Exception occurred while creating handler: {}", e.getMessage());
                throw e;
            }
        }


    }

    // Delete a Handler by its UUID
    public static void deleteHandler(long id) throws Exception {
        synchronized (lock) {
            try {
                Handler handler = storage.get(id);
                if (handler == null) {
                    throw new Exception(String.format("Handler with id %s, does not exist", id));
                }

                if (!handler.stop2()) {
                    throw new Exception("Error stopping handler");
                } else {
                    storage.remove(id);
                }
            } catch (Exception e) {
                log.error("Exception occurred while deleting handler: {}", e.getMessage());
                throw e;
            }
        }
    }

    public static void stopTunnel(String name, String reqId) throws Exception {
        synchronized (lock) {
            try {
                Handler handler;
                if (reqId != null) {

                    handler = storage.get(Long.parseLong(reqId));//IMPORTANTTTTTTTTTTTTTTTTTT
                    if (handler == null) {
                        throw new Exception(String.format("Handler with id %s does not exist", reqId));
                    }
                } else if (name != null) {
                    Long reqId_aux = findHandlerKeyContaining(name);
                    if (reqId_aux == null) {
                        reqId_aux = findHandlerKeyContaining(name + "_stopped");
                        if (reqId_aux == null) {
                            throw new Exception(String.format("Handler with name %s does not exist", name));
                        }
                    }
                    handler = storage.get(reqId_aux);
                } else {
                    throw new Exception("RequestDeleteDTO must contain either reqId or name");
                }

                if (handler.isStopped()) {
                    log.info("Handler {} is already stopped", reqId != null ? reqId : name);
                    return;
                }

                if (!handler.stop()) {
                    throw new Exception("Error stopping handler");
                } else {
                    storage.remove(name != null ? reqId : findHandlerKeyContaining(name));

                    //log.info("Handler {} removed after stopping", request_del.getReqId() != null ? request_del.getReqId() : request_del.getName());
                }
            } catch (Exception e) {
                log.error("Exception occurred while stopping tunnel: {}", e.getMessage());
                throw e;
            }

        }
    }

    public static void rekey(String name_spi) throws Exception {
        synchronized (lock) {
            try {
                String[] s = name_spi.split("_");
                if (s.length < 2) {
                    throw new Exception("The id of the SAD notification is incorrect");
                }
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




    public static Long findHandlerKeyContaining(String key) {

        for (Map.Entry<Long, Handler> entry : storage.entrySet()) {
            if (entry.getValue().keyExists(key)) {
                return entry.getKey();
            }
        }
        return null;

    }
}




