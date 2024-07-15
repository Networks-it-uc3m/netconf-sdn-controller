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
import java.util.HashSet;
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
    private boolean isStopped=false;

    public Handler (NetconfSession newDeviceSession_1, NetconfSession newDeviceSession_2, IpsecConfig cfg1, IpsecConfig cfg2){
        this.ids.put(cfg1.getName(), new OutIn(cfg1, newDeviceSession_1, newDeviceSession_2 ,cfg1.getOrigin(),cfg1.getEnd()));
        this.ids.put(cfg2.getName(), new OutIn(cfg2, newDeviceSession_2, newDeviceSession_1,cfg2.getOrigin(),cfg2.getEnd()));
        this.configs[0]=cfg1;
        this.configs[1]=cfg2;
    }

    public static Handler newHandler(request request, long id, NetconfSession newDeviceSession_1, NetconfSession newDeviceSession_2) throws Exception {
        IpsecConfig.IPsecConfigType mode;

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

        IpsecConfig cfg2 = new IpsecConfig(
                request.getNode2(),
                request.getNode1(),
                request.getSoftLifetime(),
                request.getHardLifetime(),
                mode,
                cryptoConfig,
                id
        );

        if ((cfg1 == null)||(cfg2 == null)) {
            throw new Exception("Failed to create configurations");
        }

        return new Handler(newDeviceSession_1, newDeviceSession_2, cfg1, cfg2);
    }

    public boolean setInitialConfigValues(NetconfSession newDeviceSession_1, NetconfSession newDeviceSession_2) throws NetconfException {
        String[] spd1 = new String[2];
        String[] spd2 = new String[2];
        String[] sad1 = new String[2];
        String[] sad2 = new String[2];

        String[] result1 = this.configs[0].createSPDConfig();

        spd1[0] = result1[0];
        spd2[0] = result1[1];

        String[] result2 = this.configs[1].createSPDConfig();

        spd2[1] = result2[0];
        spd1[1] = result2[1];

        String[] result3 = this.configs[0].createSADConfig();

        sad1[0] = result3[0];
        sad2[0] = result3[1];

        String[] result4 = this.configs[1].createSADConfig();

        sad2[1] = result4[0];
        sad1[1] = result4[1];

        log.info("Generated configuration values");

        String s1DataIn = generateI2NSFConfig(new String[]{sad1[1],null}, spd1);
        String s2DataIn = generateI2NSFConfig (new String[]{sad2[0],null},spd2) ;
        String s1DataOut = generateI2NSFConfig(new String[]{sad1[0],null}, new String[]{null,null});
        String s2DataOut = generateI2NSFConfig(new String[]{sad2[1],null}, new String[]{null,null});

        try {
            newDeviceSession_1.editConfig(DatastoreId.datastore("running"), "merge", s1DataIn);

        } catch (NetconfException e) {
            log.error("Error setting s1DataIn config: {}", e.getMessage());
            try {
                newDeviceSession_1.editConfig(DatastoreId.datastore("running"), "merge", s1DataIn);
                log.info("Second attempt to execute editConfig for s1DataIn succeeded");
            } catch (NetconfException ex) {
                log.error("Second attempt to execute editConfig for s1DataIn failed: {}", ex.getMessage());
            }
            return false;
        }

        try {
            newDeviceSession_2.editConfig(DatastoreId.datastore("running"), "merge", s2DataIn);
        } catch (NetconfException e) {
            log.error("Error setting s2DataIn config: {}", e.getMessage());
            try {
                newDeviceSession_2.editConfig(DatastoreId.datastore("running"), "merge", s2DataIn);
                log.info("Second attempt to execute editConfig for s2DataIn succeeded");
            } catch (NetconfException ex) {
                log.error("Second attempt to execute editConfig for s2DataIn failed: {}", ex.getMessage());
            }
            return false;
        }

        try {
            newDeviceSession_1.editConfig(DatastoreId.datastore("running"), "merge", s1DataOut);
        } catch (NetconfException e) {
            log.error("Error setting s1DataOut config: {}", e.getMessage());
            try {
                newDeviceSession_1.editConfig(DatastoreId.datastore("running"), "merge", s1DataOut);
                log.info("Second attempt to execute editConfig for s1DataOut succeeded");
            } catch (NetconfException ex) {
                log.error("Second attempt to execute editConfig for s1DataOut failed: {}", ex.getMessage());
            }
            return false;
        }

        try {
            newDeviceSession_2.editConfig(DatastoreId.datastore("running"), "merge", s2DataOut);
        } catch (NetconfException e) {
            log.error("Error setting s2DataOut config: {}", e.getMessage());
            try {
                newDeviceSession_2.editConfig(DatastoreId.datastore("running"), "merge", s2DataOut);
                log.info("Second attempt to execute editConfig for s2DataOut succeeded");
            } catch (NetconfException ex) {
                log.error("Second attempt to execute editConfig for s2DataOut failed: {}", ex.getMessage());
            }
            return false;
        }
        return true;
    }

    public boolean processRekey(NetconfController controller, String name, long oldSPI) throws Exception {
        if (this.isStopped) {
            return false;
        }

        log.info("Soft lifetime expired:\tReqId : " + this.ids.get(name).getCfg().getReqId() + "\t\tSPI:"+oldSPI+"\t\t\t\t"+name);

        if (this.ids.get(name).getCfg().getReKeysDone().getOrDefault(oldSPI, false)) {
            log.info("Rekey of spi: " + oldSPI + " has been already completed");
            return true;
        } else if (this.ids.get(name).getCfg().getSpi() != oldSPI) {
            log.info("Configuration does not contain this SPI: " + oldSPI);
            return false;
        }

        this.ids.get(name).getCfg().getReKeysDone().put(oldSPI, true);

        String delSADXml = this.ids.get(name).getCfg().createDelSAD(oldSPI);

        this.ids.get(name).getCfg().getCryptoConfig().setNewCryptoValues();
        this.ids.get(name).getCfg().setNewSpi();

        String[] sadConfig = this.ids.get(name).getCfg().createSADConfig();
        String s1Data = generateI2NSFConfig(new String[]{sadConfig[0], null}, new String[]{null, null});
        String s2Data = generateI2NSFConfig(new String[]{sadConfig[1], null}, new String[]{null, null});
        String mode = "merge";

        try {
            this.ids.get(name).getS1().editConfig(DatastoreId.datastore("running"), mode, s1Data);
        } catch (NetconfException e) {
            log.error("Failed to execute editConfig for s1Data: {}",e.getMessage());
            try {
                this.ids.get(name).getS1().editConfig(DatastoreId.datastore("running"), mode, s1Data);
                log.info("Second attempt to execute editConfig for s1Data succeeded");
            } catch (NetconfException ex) {
                log.error("Second attempt to execute editConfig for s1Data failed: {}", ex.getMessage());
            }
        }

        try {
            this.ids.get(name).getS2().editConfig(DatastoreId.datastore("running"), mode, s2Data);
        } catch (NetconfException e) {
            log.error("Failed to execute editConfig for s2Data: {}",e.getMessage());
            try {
                this.ids.get(name).getS2().editConfig(DatastoreId.datastore("running"), mode, s2Data);
                log.info("Second attempt to execute editConfig for s2Data succeeded");
            } catch (NetconfException ex) {
                log.error("Second attempt to execute editConfig for s2Data failed: {}", ex.getMessage());
            }
        }

        //log.info("Deleting old entries out " + this.ids.get(name).getCfg().getOrigin() + " in " + this.ids.get(name).getCfg().getEnd() + " SPI " + oldSPI);

        try {
            this.ids.get(name).getS1().editConfig(DatastoreId.datastore("running"), mode, delSADXml);
        } catch (NetconfException e) {
            log.error("Failed to execute editConfig for delSAD: {}",e.getMessage());
            try {
                //this.ids.get(name).getS1().checkAndReestablish();
                this.ids.get(name).getS1().editConfig(DatastoreId.datastore("running"), mode, delSADXml);
                log.info("Second attempt to execute editConfig for delSAD succeeded");
            } catch (NetconfException ex) {
                if (ex.getMessage().contains("Node \"sad-entry\" to be deleted does not exist.")) {
                    log.warn("Agent deleted the SAD but reply not received: "+ex.getMessage());
                } else {
                    log.error("Second attempt to execute editConfig for delSAD failed: {}", ex.getMessage());
                }
            }
        }

        try {
            this.ids.get(name).getS2().editConfig(DatastoreId.datastore("running"), mode, delSADXml);
        } catch (NetconfException e) {
            log.error("Failed to execute editConfig for delSAD: {}",e.getMessage());
            try {
                this.ids.get(name).getS2().editConfig(DatastoreId.datastore("running"), mode, delSADXml);
                log.info("Second attempt to execute editConfig for delSAD succeeded");
            } catch (NetconfException ex) {
                if (ex.getMessage().contains("Node \"sad-entry\" to be deleted does not exist.")) {
                    log.warn("Agent deleted the SAD but reply not received: "+ex.getMessage());
                } else {
                    log.error("Second attempt to execute editConfig for delSAD failed: {}", ex.getMessage());
                }
            }
        }

        log.info("Rekey process completed:\tReqId : " + this.ids.get(name).getCfg().getReqId() + "\t\toldSPI:"+oldSPI+" --> newSPI:"+this.ids.get(name).getCfg().getSpi()+"\t\t"+name);

        return true;
    }

    public boolean stop() {
        for (OutIn outIn : ids.values()) {
            String delSADXml = outIn.getCfg().createDelSAD();
            String delSPDXml = outIn.getCfg().createDelSPD();
            String mode = "merge";
            try {
                outIn.getS1().editConfig(DatastoreId.datastore("running"), mode, delSADXml);
            } catch (Exception e) {
                log.error("Error deleting SAD: {}", e.getMessage());
            }
            try {
                outIn.getS2().editConfig(DatastoreId.datastore("running"), mode, delSADXml);
            } catch (Exception e) {
                log.error("Error deleting SAD: {}", e.getMessage());
            }

            try {
                outIn.getS1().editConfig(DatastoreId.datastore("running"), mode, delSPDXml);
            } catch (Exception e) {
                log.error("Error deleting SPD: {}", e.getMessage());
            }
            try {
                outIn.getS2().editConfig(DatastoreId.datastore("running"), mode, delSPDXml);
            } catch (Exception e) {
                log.error("Error deleting SPD: {}", e.getMessage());
            }
        }
        for (String key : new HashSet<>(ids.keySet())) {
            ids.put(key + "_stopped", ids.remove(key));
        }
        this.setStopped(true);
        return true;
    }

    public boolean delete() {
        for (OutIn outIn : ids.values()) {
            String delSADXml = outIn.getCfg().createDelSAD();
            String delSPDXml = outIn.getCfg().createDelSPD();
            String mode = "merge";
            try {
                outIn.getS1().editConfig(DatastoreId.datastore("running"), mode, delSADXml);
            } catch (Exception e) {
                log.error("Error deleting SAD: {}", e.getMessage());
            }
            try {
                outIn.getS2().editConfig(DatastoreId.datastore("running"), mode, delSADXml);
            } catch (Exception e) {
                log.error("Error deleting SAD: {}", e.getMessage());
            }
            try {
                outIn.getS1().editConfig(DatastoreId.datastore("running"), mode, delSPDXml);
            } catch (Exception e) {
                log.error("Error deleting SPD: {}", e.getMessage());
            }
            try {
                outIn.getS2().editConfig(DatastoreId.datastore("running"), mode, delSPDXml);
            } catch (Exception e) {
                log.error("Error deleting SPD: {}", e.getMessage());
            }
        }
        return true;
    }

    public boolean keyExists(String key) {
        return ids.containsKey(key);
    }

    public boolean isStopped() {
        return this.isStopped;
    }

    public void setStopped(boolean stopped) {
        this.isStopped = stopped;
    }


    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("========== Handler Details ================================================================\n");
        sb.append("Status: ").append(isStopped ? "Stopped" : "Running").append("\n");
        sb.append("Configuration IDs:\n");
        ids.forEach((key, value) -> {
            sb.append(value).append("\n");
        });
        sb.append("===========================================================================================\n");
        return sb.toString();
    }
}




