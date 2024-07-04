package org.ccipstest.app;
import org.onosproject.mastership.MastershipService;
import org.onosproject.net.DeviceId;
import org.onosproject.net.driver.DriverHandler;
import org.onosproject.netconf.DatastoreId;
import org.onosproject.netconf.NetconfController;
import org.onosproject.netconf.NetconfException;
import org.onosproject.netconf.NetconfSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.logging.ErrorManager;

import static org.ccipstest.Templates.TemplateManager.generateI2NSFConfig;
import static org.ccipstest.app.Algs.AUTHALGS;
import static org.ccipstest.app.Algs.ENCALGS;

import org.onosproject.net.driver.DriverHandler;


public class Handler {
    private static final Logger log = LoggerFactory.getLogger(Handler.class);
    private IpsecConfig[] configs =new IpsecConfig[2];

    private Map<String, OutIn> ids = new HashMap<>();
    private ReentrantReadWriteLock locker = null;
    private boolean isStopped=false;


    public Handler (NetconfSession newDeviceSession_1, NetconfSession newDeviceSession_2, IpsecConfig cfg1, IpsecConfig cfg2){
        this.locker = new ReentrantReadWriteLock();;

        this.ids.put(cfg1.getName(), new OutIn(cfg1, newDeviceSession_1, newDeviceSession_2 ,cfg1.getOrigin(),cfg1.getEnd()));
        this.ids.put(cfg2.getName(), new OutIn(cfg2, newDeviceSession_2, newDeviceSession_1,cfg2.getOrigin(),cfg2.getEnd()));
        this.configs[0]=cfg1;
        this.configs[1]=cfg2;
    }

    public static Handler newHandler(request request, long id, NetconfSession newDeviceSession_1, NetconfSession newDeviceSession_2) throws Exception {
//        String node1 = request.getNode1().getIpControl();
//        String node2 = request.getNode2().getIpControl();
        IpsecConfig.IPsecConfigType mode;

        // Check mode:
        if (request.getNode1().getNetworkInternal()==null) {
            mode = IpsecConfig.IPsecConfigType.H2H;
            log.info("New Handler for H2H mode");
        } else {
            mode = IpsecConfig.IPsecConfigType.G2G;
            log.info("New Handler for G2G mode");
        }

        Algs.EncAlgType encAlg;
        Algs.AuthAlgType authAlg;

        if (!ENCALGS.containsKey(request.getEncAlg())) {
            throw new Exception(String.format("ENC algorithm not found: %s", request.getEncAlg()));
        } else {
            encAlg = ENCALGS.get(request.getEncAlg());
        }

        if (!AUTHALGS.containsKey(request.getIntAlg())) {
            throw new Exception(String.format("AUTH algorithm not found: %s", request.getIntAlg()));
        } else {
            authAlg = AUTHALGS.get(request.getIntAlg());
        }

        CryptoConfig cryptoConfig = new CryptoConfig(encAlg, authAlg);

        IpsecConfig cfg1 = new IpsecConfig(
                request.getNode1(),
                request.getNode2(),
                request.getSoftLifetime(),
                request.getHardLifetime(),
                mode,
                cryptoConfig,
                id
        );

        if (cfg1 == null) {
            throw new Exception("Failed to create config 1");
        }

        IpsecConfig cfg2 = new IpsecConfig(
                request.getNode2(),
                request.getNode1(),
                request.getSoftLifetime(),
                request.getHardLifetime(),
                mode,
                cryptoConfig,
                id
        );

        if (cfg2 == null) {
            throw new Exception("Failed to create config 2");
        }


        return new Handler(newDeviceSession_1, newDeviceSession_2, cfg1, cfg2);
    }

    public boolean setInitialConfigValues(NetconfSession newDeviceSession_1, NetconfSession newDeviceSession_2) throws NetconfException {
        String[] spd1 = new String[2];
        String[] spd2 = new String[2];
        String[] sad1 = new String[2];
        String[] sad2 = new String[2];
        String err;

        // Set spd1 outbound and spd2 inbound
        String[] result1 = this.configs[0].createSPDConfig();

        spd1[0] = result1[0];
        spd2[0] = result1[1];

        // Set spd2 outbound and spd1 inbound
        String[] result2 = this.configs[1].createSPDConfig();

        spd2[1] = result2[0];
        spd1[1] = result2[1];

        // Set sad1 outbound and sad2 inbound
        String[] result3 = this.configs[0].createSADConfig();

        sad1[0] = result3[0];
        sad2[0] = result3[1];

        // Set sad2 outbound and sad1 inbound
        String[] result4 = this.configs[1].createSADConfig();

        sad2[1] = result4[0];
        sad1[1] = result4[1];

        log.info("Generated configuration values");

        // Now format the data
        String s1DataIn = generateI2NSFConfig(new String[]{sad1[1],null}, spd1);
        String s2DataIn = generateI2NSFConfig (new String[]{sad2[0],null},spd2) ;
        String s1DataOut = generateI2NSFConfig(new String[]{sad1[0],null}, new String[]{null,null});
        String s2DataOut = generateI2NSFConfig(new String[]{sad2[1],null}, new String[]{null,null});

        // This setup is necessary so no traffic is lost when the SA are established
        // Setup first inbound configs
        try {
            newDeviceSession_1.editConfig(DatastoreId.datastore("running"), "merge", s1DataIn);

        } catch (NetconfException e) {
            log.error("Error setting s1DataIn config: {}", e.getMessage());
            return false;
        }

        try {
            newDeviceSession_2.editConfig(DatastoreId.datastore("running"), "merge", s2DataIn);

        } catch (NetconfException e) {
            log.error("Error setting s2DataIn config: {}", e.getMessage());
            return false;
        }

        // Then setup outbounds configs
        try {
            newDeviceSession_1.editConfig(DatastoreId.datastore("running"), "merge", s1DataOut);

        } catch (NetconfException e) {
            log.error("Error setting s1DataOut config: {}", e.getMessage());
            return false;
        }

        try {
            newDeviceSession_2.editConfig(DatastoreId.datastore("running"), "merge", s2DataOut);

        } catch (NetconfException e) {
            log.error("Error setting s2DataOut config: {}", e.getMessage());
            return false;
        }

        return true;
    }

    public boolean processRekey(NetconfController controller,MastershipService mastershipService, String name, long oldSPI) throws Exception {

        this.locker.writeLock().lock();



        String uri_device_1 = "netconf:" + this.ids.get(name).getS1_string() + ":830";
        String uri_device_2 = "netconf:" + this.ids.get(name).getS2_string() + ":830";
        DeviceId new_device_1 = DeviceId.deviceId(uri_device_1);
        DeviceId new_device_2 = DeviceId.deviceId(uri_device_2);




//        NetconfSession newDeviceSession_1 = controller.getNetconfDevice(new_device_1).getSession();
//        NetconfSession newDeviceSession_2 = controller.getNetconfDevice(new_device_2).getSession();
        NetconfSession newDeviceSession_1 = controller.getNetconfDevice(new_device_1).getSession();
        NetconfSession newDeviceSession_2 = controller.getNetconfDevice(new_device_2).getSession();



//        controller.pingDevice(new_device_1);
//        controller.pingDevice(new_device_2);
        this.ids.get(name).setS1(newDeviceSession_1);
        this.ids.get(name).setS2(newDeviceSession_2);

        if (this.isStopped) {
            return false;
        }

//        mastershipService.getMasterFor(new_device_1);
//        mastershipService.getMasterFor(new_device_2);

        System.out.print("Received notification to proceed with rekey of " + name + oldSPI);

        if (!this.ids.get(name).getCfg().getReKeysDone().getOrDefault(oldSPI, false)) {//CUIDAOOOOOOO ESTE CAMBIO DE !
            System.out.print("Rekey of spi:" + oldSPI + " has been already completed\n");
            return true;
        } else if (this.ids.get(name).getCfg().getSpi() != oldSPI) {
            System.out.print("Configuration does not contain this SPI: " + oldSPI + "\n");
            return false;
        }

        this.ids.get(name).getCfg().getReKeysDone().put(oldSPI, true);


        System.out.print("Timer for" + this.ids.get(name).getCfg().getName() + " has expired. Proceed to setup new SADs\n");
        String delSADXml = this.ids.get(name).getCfg().createDelSAD(oldSPI);

        this.ids.get(name).getCfg().getCryptoConfig().setNewCryptoValues();
        this.ids.get(name).getCfg().setNewSpi();

        String[] sadConfig = this.ids.get(name).getCfg().createSADConfig();
        String s1Data = generateI2NSFConfig(new String[]{sadConfig[0], null}, new String[]{null, null});
        String s2Data = generateI2NSFConfig(new String[]{sadConfig[1], null}, new String[]{null, null});

        String mode = "merge";
//        while (!mastershipservice.isLocalMaster(new_device_1)){
//            mastershipservice.requestRoleForSync(new_device_1);
//        }
//        try {
//            this.ids.get(name).getS1().checkAndReestablish();
//        } catch (NetconfException e) {
//            log.error("Failed to check and reestablish session 1");
//        }


        newDeviceSession_1.getConfig(DatastoreId.datastore("running"));
        try {
            this.ids.get(name).getS1().editConfig(DatastoreId.datastore("running"), mode, s1Data);
        } catch (NetconfException e) {
            log.error("Failed editconfig s1Data");
        }

//        while (!mastershipservice.isLocalMaster(new_device_2)){
//            mastershipservice.requestRoleForSync(new_device_2);
//        }
//        try {
//            this.ids.get(name).getS2().checkAndReestablish();
//        } catch (NetconfException e){
//            log.error("Failed to check and reestablish session 2");
//        }
        try {
            this.ids.get(name).getS2().editConfig(DatastoreId.datastore("running"), mode, s2Data);
        } catch (NetconfException e) {
            log.error("Failed editconfig s2Data");
        }
//
//        newDeviceSession_1.checkAndReestablish();
//        newDeviceSession_2.checkAndReestablish();
//
        System.out.print("Deleting old entries out " + this.ids.get(name).getCfg().getOrigin() + " in " + this.ids.get(name).getCfg().getEnd() + " SPI " + oldSPI);
//        while (!mastershipservice.isLocalMaster(new_device_1)){
//            mastershipservice.requestRoleForSync(new_device_1);
//        }
//        try {
//            this.ids.get(name).getS1().checkAndReestablish();
//        } catch (NetconfException e) {
//            log.error("Failed to check and reestablish session 1");
//        }
        try {
            this.ids.get(name).getS1().editConfig(DatastoreId.datastore("running"), mode, delSADXml);
        } catch (NetconfException e) {
            log.error("Failed editconfig delSAD");
        }
//        while (!mastershipservice.isLocalMaster(new_device_2)){
//            mastershipservice.requestRoleForSync(new_device_2);
//        }
//        try {
//            this.ids.get(name).getS2().checkAndReestablish();
//        } catch (NetconfException e) {
//            log.error("Failed to check and reestablish session 2");
//        }
        try {
            this.ids.get(name).getS2().editConfig(DatastoreId.datastore("running"), mode, delSADXml);
        } catch (NetconfException e) {
            log.error("Failed editconfig delSAD");
        }

        System.out.print("Rekey process of " + this.ids.get(name).getCfg().getReqId() + " already completed");

        this.locker.writeLock().unlock();

        return true;
    }




    public boolean keyExists(String key) {
        this.locker.readLock().lock();
        try {
            return ids.containsKey(key);
        } finally {
            this.locker.readLock().unlock();
        }
    }


    public boolean stop() {
        this.locker.writeLock().lock();
        try {
            ErrorManager log;
            for (OutIn outIn : ids.values()) {
                // Generate del SADs
                String delSADXml = outIn.getCfg().createDelSAD();

                // Generate del SPDs
                String delSPDXml = outIn.getCfg().createDelSPD();
                String mode="merge";

                // Delete SADs
                // First delete the outbound configs
                // Then delete the inbound configs
                try {
                    outIn.getS1().editConfig(DatastoreId.datastore("running"),mode,delSADXml);
                } catch (Exception e) {
                    System.out.print("Error");
                }
                try {
                    outIn.getS2().editConfig(DatastoreId.datastore("running"),mode,delSADXml);
                } catch (Exception e) {
                    System.out.print("Error");
                }

                // Delete SPDs
                try {
                    outIn.getS1().editConfig(DatastoreId.datastore("running"),mode,delSPDXml);
                } catch (Exception e) {
                    System.out.print("Error");
                }
                try {
                    outIn.getS2().editConfig(DatastoreId.datastore("running"),mode,delSPDXml);
                } catch (Exception e) {
                    System.out.print("Error");
                }
            }

            isStopped = true;
//            for (NetconfSession s : sessions) {
//                //
//                try {
//                    s.close();
//                } catch (Exception e) {
//                    log.error(e.getMessage());
//                }
//            }

            return true;
        } finally {
            this.locker.writeLock().unlock();
        }
    }

    // Placeholder for the editConfig method





    public boolean isStopped() {
        return this.isStopped;
    }
    public void setStopped(boolean stopped) {
        this.isStopped = stopped;
    }

    @Override
    public String toString() {
        return "Handler{" +
                "isStopped=" + isStopped +
                ", ids=" + ids +
                "}\n";
    }
}




