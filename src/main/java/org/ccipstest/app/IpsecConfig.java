package org.ccipstest.app;


import org.ccipstest.Templates.TemplateManager;


import java.util.HashMap;
import java.util.Map;

import java.util.concurrent.ThreadLocalRandom;

public class IpsecConfig {
    //public static int id=1; ///PARA ASIGNARLO

    private IPsecConfigType confType;

    public void setName(String name) {
        this.name = name;
    }

    private String name;


    private long spi;
    private long reqId;
    // Config Addresses
    private String origin; // Always outbound
    private String end;    // Always inbound
    // Prefix addresses only for g2g case
    private String prefixOrigin = null;
    private String prefixEnd = null;
    // Data Addresses
    private String dataOrigin;
    private String dataEnd;
    // Crypto data
    private CryptoConfig cryptoConfig;
    // Lifetime config
    private LifetimeConfig softLifetime;
    private LifetimeConfig hardLifetime;
    // Last rekey
    private long timestamp;

    private Map<Long, Boolean> reKeysDone;

    public IPsecConfigType getConfType() {
        return confType;
    }

    public String getName() {
        return this.name;
    }

    public long getSpi() {
        return this.spi;
    }

    public void setNewSpi() {
        this.spi = SPIManager.getNewSPI();
        this.name = String.format("out/%s/in/%s", this.getDataOrigin(), this.getDataEnd());
    }


    public long getReqId() {
        return this.reqId;
    }

    public String getOrigin() {
        return this.origin;
    }

    public String getEnd() {
        return this.end;
    }

    public String getPrefixOrigin() {
        return this.prefixOrigin;
    }

    public String getPrefixEnd() {
        return this.prefixEnd;
    }

    public String getDataOrigin() {
        return this.dataOrigin;
    }

    public String getDataEnd() {
        return this.dataEnd;
    }

    public CryptoConfig getCryptoConfig() {
        return this.cryptoConfig;
    }

    public LifetimeConfig getSoftLifetime() {
        return this.softLifetime;
    }

    public LifetimeConfig getHardLifetime() {
        return this.hardLifetime;
    }

    public long getTimestamp() {
        return this.timestamp;
    }


    public Map<Long, Boolean> getReKeysDone() {
        return this.reKeysDone;
    }

    //    @Override
//    public String toString() {
//        return "IpsecConfig{" +
//                "confType=" + confType +
//                ", name='" + name + '\'' +
//                ", spi=" + spi +
//                ", reqId=" + reqId +
//                ", origin='" + origin + '\'' +
//                ", end='" + end + '\'' +
//                ", prefixOrigin='" + prefixOrigin + '\'' +
//                ", prefixEnd='" + prefixEnd + '\'' +
//                ", dataOrigin='" + dataOrigin + '\'' +
//                ", dataEnd='" + dataEnd + '\'' +
//                ", cryptoConfig=" + cryptoConfig +
//                ", softLifetime=" + softLifetime +
//                ", hardLifetime=" + hardLifetime +
//                ", timestamp=" + timestamp +
//                ", reKeysDone=" + reKeysDone +
//                "}\n";
//    }
    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("Configuration Type: ").append(confType).append("\n");
        sb.append("Name: ").append(name).append("\n");
        sb.append("SPI: ").append(spi).append("\n");
        sb.append("Request ID: ").append(reqId).append("\n");
        sb.append("Origin: ").append(origin).append("\n");
        sb.append("End: ").append(end).append("\n");
        sb.append("Prefix Origin: ").append(prefixOrigin != null ? prefixOrigin : "N/A").append("\n");
        sb.append("Prefix End: ").append(prefixEnd != null ? prefixEnd : "N/A").append("\n");
        sb.append("Data Origin: ").append(dataOrigin).append("\n");
        sb.append("Data End: ").append(dataEnd).append("\n");
        sb.append("Crypto Configuration: ").append(cryptoConfig).append("\n");
        sb.append("Soft Lifetime: ").append(softLifetime).append("\n");
        sb.append("Hard Lifetime: ").append(hardLifetime).append("\n");
        sb.append("Timestamp: ").append(timestamp).append("\n");
        sb.append("Rekeys Done: ").append(reKeysDone).append("\n");
        return sb.toString();
    }


    public enum IPsecConfigType {
        // H2H Used for host to host configuration
        H2H(0),
        // G2G Used for gateway to gateway configuration
        G2G(1);

        private final int value;

        IPsecConfigType(int value) {
            this.value = value;
        }

        public int getValue() {
            return value;
        }

        public static IPsecConfigType fromValue(int value) {
            for (IPsecConfigType type : values()) {
                if (type.value == value) {
                    return type;
                }
            }
            throw new IllegalArgumentException("Invalid value: " + value);
        }
    }

    public IpsecConfig (Node node1,Node node2,LifetimeConfig softLifetime,LifetimeConfig hardLifetime,IPsecConfigType configType,CryptoConfig cryptoCfg, long id) {

        this.reKeysDone = new HashMap<>();
        this.confType = configType;
        this.spi = SPIManager.getNewSPI();
        this.name = String.format("out/%s/in/%s", node1.getIpData(), node2.getIpData());

        this.origin = node1.getIpControl();
        this.end = node2.getIpControl();

        if (this.confType == IPsecConfigType.G2G) {
            // Setup internal networks
            this.prefixOrigin = node1.getNetworkInternal();
            this.prefixEnd = node2.getNetworkInternal();
        }

        // Set data IPs
        this.dataOrigin = node1.getIpData();
        this.dataEnd = node2.getIpData();


        //this.timestamp = Instant.now().getEpochSecond();

        this.reqId = id;
        System.out.printf("Generated reqId is %d%n", this.reqId);

        // Setup crypto config
        this.cryptoConfig = cryptoCfg;
        this.cryptoConfig.setNewCryptoValues();

        // Lifetime
        this.softLifetime = softLifetime;
        this.hardLifetime = hardLifetime;
    }

    // Methods to create configurations
    public String createDelSAD() {
        return TemplateManager.formatDelSAD(this);
    }
    public String createDelSAD(long oldSPI) {
        return TemplateManager.formatDelSAD(this,oldSPI);
    }

    public String createDelSPD() {
        return TemplateManager.formatDelSPD(this);
    }

    public String[] createSADConfig() {
        String outCfg;
        String inCfg;
        if (this.confType == IPsecConfigType.G2G) {
            outCfg = TemplateManager.formatG2GSADValues(this, this.prefixOrigin, this.prefixEnd, this.dataOrigin, this.dataEnd);
            inCfg = TemplateManager.formatG2GSADValues(this, this.prefixOrigin, this.prefixEnd, this.dataOrigin, this.dataEnd);
        } else {
            outCfg = TemplateManager.formatH2HSADValues(this, this.dataOrigin, this.dataEnd,this.dataOrigin, this.dataEnd);
            inCfg = TemplateManager.formatH2HSADValues(this, this.dataOrigin, this.dataEnd,this.dataOrigin, this.dataEnd);
        }
        return new String[]{outCfg, inCfg};
    }

    public String[] createSPDConfig() {
        String outCfg;
        String inCfg;
        if (this.confType == IPsecConfigType.G2G) {
            outCfg = TemplateManager.formatG2GSPDValues(this, this.prefixOrigin, this.prefixEnd, this.dataOrigin, this.dataEnd, "outbound");
            inCfg = TemplateManager.formatG2GSPDValues(this, this.prefixOrigin, this.prefixEnd, this.dataOrigin, this.dataEnd, "inbound");
        } else {
            outCfg = TemplateManager.formatH2HSPDValues(this, this.dataOrigin, this.dataEnd, "outbound");
            inCfg = TemplateManager.formatH2HSPDValues(this, this.dataOrigin, this.dataEnd, "inbound");
        }
        return new String[]{outCfg, inCfg};
    }



}
