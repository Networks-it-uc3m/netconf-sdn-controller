package org.ccips.Templates;

import org.ccips.app.config.IpsecConfig;

public class TemplateManager {

    private static final String IPSEC_IKELESS_NAMESPACE = "xmlns=\"urn:ietf:params:xml:ns:yang:ietf-i2nsf-ikeless\" xmlns:nc=\"urn:ietf:params:xml:ns:netconf:base:1.0\"";
    private static final String EXT_SEQ_NUM_TRUE = "<ext-seq-num>true</ext-seq-num>";
    private static final String SEQ_OVERFLOW_FALSE = "<seq-overflow>false</seq-overflow>";
    private static final String PROTOCOL_PARAMETERS_ESP = "<protocol-parameters>esp</protocol-parameters>";
    private static final String MODE_TUNNEL = "<mode>tunnel</mode>";
    private static final String INNER_PROTOCOL_ANY = "<inner-protocol>any</inner-protocol>";
    private static final String ACTION_PROTECT = "<action>protect</action>";

    public static String byteArrayToHexString(byte[] byteArray) {
        StringBuilder hexString = new StringBuilder();
        for (int i = 0; i < byteArray.length; i++) {
            hexString.append(String.format("%02X", byteArray[i]));
            if (i < byteArray.length - 1) {
                hexString.append(":");
            }
        }
        return hexString.toString();
    }

    public static String formatG2GSADValues(IpsecConfig config, String localPrefix, String remotePrefix, String local, String remote) {
        return new StringBuilder()
                .append("<sad-entry>")
                .append("<name>").append(config.getName()).append("_").append(config.getSpi()).append("</name>")
                .append("<reqid>").append(config.getReqId()).append("</reqid>")
                .append("<ipsec-sa-config>")
                .append("<spi>").append(config.getSpi()).append("</spi>")
                .append(EXT_SEQ_NUM_TRUE)
                .append(SEQ_OVERFLOW_FALSE)
                .append("<traffic-selector>")
                .append("<local-prefix>").append(localPrefix).append("</local-prefix>")
                .append("<remote-prefix>").append(remotePrefix).append("</remote-prefix>")
                .append(INNER_PROTOCOL_ANY)
                .append("</traffic-selector>")
                .append(PROTOCOL_PARAMETERS_ESP)
                .append(MODE_TUNNEL)
                .append("<esp-sa>")
                .append("<encryption>")
                .append("<encryption-algorithm>").append(config.getCryptoConfig().getEncAlg().getValue()).append("</encryption-algorithm>")
                .append("<key>").append(byteArrayToHexString(config.getCryptoConfig().getEncKey())).append("</key>")
                .append("<iv>").append(byteArrayToHexString(config.getCryptoConfig().getIv())).append("</iv>")
                .append("</encryption>")
                .append("<integrity>")
                .append("<integrity-algorithm>").append(config.getCryptoConfig().getIntAlg().getValue()).append("</integrity-algorithm>")
                .append("<key>").append(byteArrayToHexString(config.getCryptoConfig().getIntKey())).append("</key>")
                .append("</integrity>")
                .append("</esp-sa>")
                .append("<sa-lifetime-hard>")
                .append("<bytes>").append(config.getHardLifetime().getnBytes()).append("</bytes>")
                .append("<packets>").append(config.getHardLifetime().getnPackets()).append("</packets>")
                .append("<time>").append(config.getHardLifetime().getnTime()).append("</time>")
                .append("<idle>").append(config.getHardLifetime().getnTimeIdle()).append("</idle>")
                .append("</sa-lifetime-hard>")
                .append("<sa-lifetime-soft>")
                .append("<bytes>").append(config.getSoftLifetime().getnBytes()).append("</bytes>")
                .append("<packets>").append(config.getSoftLifetime().getnPackets()).append("</packets>")
                .append("<time>").append(config.getSoftLifetime().getnTime()).append("</time>")
                .append("<idle>").append(config.getSoftLifetime().getnTimeIdle()).append("</idle>")
                .append("<action>replace</action>")
                .append("</sa-lifetime-soft>")
                .append("<tunnel>")
                .append("<local>").append(local).append("</local>")
                .append("<remote>").append(remote).append("</remote>")
                .append("</tunnel>")
                .append("</ipsec-sa-config>")
                .append("</sad-entry>")
                .toString();
    }

    public static String formatG2GSPDValues(IpsecConfig config, String localPrefix, String remotePrefix, String local, String remote, String direction) {
        return new StringBuilder()
                .append("<spd-entry>")
                .append("<name>").append(config.getName()).append("_").append(config.getSpi()).append("</name>")
                .append("<direction>").append(direction).append("</direction>")
                .append("<reqid>").append(config.getReqId()).append("</reqid>")
                .append("<ipsec-policy-config>")
                .append("<anti-replay-window-size>32</anti-replay-window-size>")
                .append("<traffic-selector>")
                .append("<local-prefix>").append(localPrefix).append("</local-prefix>")
                .append("<remote-prefix>").append(remotePrefix).append("</remote-prefix>")
                .append(INNER_PROTOCOL_ANY)
                .append("</traffic-selector>")
                .append("<processing-info>")
                .append(ACTION_PROTECT)
                .append("<ipsec-sa-cfg>")
                .append(EXT_SEQ_NUM_TRUE)
                .append(SEQ_OVERFLOW_FALSE)
                .append(MODE_TUNNEL)
                .append(PROTOCOL_PARAMETERS_ESP)
                .append("<esp-algorithms>")
                .append("<integrity>").append(config.getCryptoConfig().getIntAlg().getValue()).append("</integrity>")
                .append("<encryption>")
                .append("<id>1</id>")
                .append("<algorithm-type>").append(config.getCryptoConfig().getEncAlg().getValue()).append("</algorithm-type>")
                .append("<key-length>").append(config.getCryptoConfig().getEncKeyLength() * 8).append("</key-length>")
                .append("</encryption>")
                .append("</esp-algorithms>")
                .append("<tunnel>")
                .append("<local>").append(local).append("</local>")
                .append("<remote>").append(remote).append("</remote>")
                .append("</tunnel>")
                .append("</ipsec-sa-cfg>")
                .append("</processing-info>")
                .append("</ipsec-policy-config>")
                .append("</spd-entry>")
                .toString();
    }

    public static String formatH2HSADValues(IpsecConfig config, String localPrefix, String remotePrefix, String local, String remote) {
        return new StringBuilder()
                .append("<sad-entry>")
                .append("<name>").append(config.getName()).append("_").append(config.getSpi()).append("</name>")
                .append("<reqid>").append(config.getReqId()).append("</reqid>")
                .append("<ipsec-sa-config>")
                .append("<spi>").append(config.getSpi()).append("</spi>")
                .append(EXT_SEQ_NUM_TRUE)
                .append(SEQ_OVERFLOW_FALSE)
                .append("<traffic-selector>")
                .append("<local-prefix>").append(localPrefix).append("/32</local-prefix>")
                .append("<remote-prefix>").append(remotePrefix).append("/32</remote-prefix>")
                .append(INNER_PROTOCOL_ANY)
                .append("</traffic-selector>")
                .append(PROTOCOL_PARAMETERS_ESP)
                .append(MODE_TUNNEL)
                .append("<esp-sa>")
                .append("<encryption>")
                .append("<encryption-algorithm>").append(config.getCryptoConfig().getEncAlg().getValue()).append("</encryption-algorithm>")
                .append("<key>").append(byteArrayToHexString(config.getCryptoConfig().getEncKey())).append("</key>")
                .append("<iv>").append(byteArrayToHexString(config.getCryptoConfig().getIv())).append("</iv>")
                .append("</encryption>")
                .append("<integrity>")
                .append("<integrity-algorithm>").append(config.getCryptoConfig().getIntAlg().getValue()).append("</integrity-algorithm>")
                .append("<key>").append(byteArrayToHexString(config.getCryptoConfig().getIntKey())).append("</key>")
                .append("</integrity>")
                .append("</esp-sa>")
                .append("<sa-lifetime-hard>")
                .append("<bytes>").append(config.getHardLifetime().getnBytes()).append("</bytes>")
                .append("<packets>").append(config.getHardLifetime().getnPackets()).append("</packets>")
                .append("<time>").append(config.getHardLifetime().getnTime()).append("</time>")
                .append("<idle>").append(config.getHardLifetime().getnTimeIdle()).append("</idle>")
                .append("</sa-lifetime-hard>")
                .append("<sa-lifetime-soft>")
                .append("<bytes>").append(config.getSoftLifetime().getnBytes()).append("</bytes>")
                .append("<packets>").append(config.getSoftLifetime().getnPackets()).append("</packets>")
                .append("<time>").append(config.getSoftLifetime().getnTime()).append("</time>")
                .append("<idle>").append(config.getSoftLifetime().getnTimeIdle()).append("</idle>")
                .append("<action>replace</action>")
                .append("</sa-lifetime-soft>")
                .append("<tunnel>")
                .append("<local>").append(local).append("</local>")
                .append("<remote>").append(remote).append("</remote>")
                .append("</tunnel>")
                .append("</ipsec-sa-config>")
                .append("</sad-entry>")
                .toString();
    }

    public static String formatH2HSPDValues(IpsecConfig config, String localPrefix, String remotePrefix, String direction) {
        return new StringBuilder()
                .append("<spd-entry>")
                .append("<name>").append(config.getName()).append("_").append(config.getSpi()).append("</name>")
                .append("<direction>").append(direction).append("</direction>")
                .append("<reqid>").append(config.getReqId()).append("</reqid>")
                .append("<ipsec-policy-config>")
                .append("<anti-replay-window-size>32</anti-replay-window-size>")
                .append("<traffic-selector>")
                .append("<local-prefix>").append(localPrefix).append("/32</local-prefix>")
                .append("<remote-prefix>").append(remotePrefix).append("/32</remote-prefix>")
                .append(INNER_PROTOCOL_ANY)
                .append("</traffic-selector>")
                .append("<processing-info>")
                .append(ACTION_PROTECT)
                .append("<ipsec-sa-cfg>")
                .append(EXT_SEQ_NUM_TRUE)
                .append(SEQ_OVERFLOW_FALSE)
                .append(MODE_TUNNEL)
                .append(PROTOCOL_PARAMETERS_ESP)
                .append("<esp-algorithms>")
                .append("<integrity>").append(config.getCryptoConfig().getIntAlg().getValue()).append("</integrity>")
                .append("<encryption>")
                .append("<id>1</id>")
                .append("<algorithm-type>").append(config.getCryptoConfig().getEncAlg().getValue()).append("</algorithm-type>")
                .append("<key-length>").append(config.getCryptoConfig().getEncKeyLength() * 8).append("</key-length>")
                .append("</encryption>")
                .append("</esp-algorithms>")
                .append("<tunnel>")
                .append("<local>").append(localPrefix).append("</local>")
                .append("<remote>").append(remotePrefix).append("</remote>")
                .append("</tunnel>")
                .append("</ipsec-sa-cfg>")
                .append("</processing-info>")
                .append("</ipsec-policy-config>")
                .append("</spd-entry>")
                .toString();
    }

    public static String formatDelSAD(IpsecConfig config) {
        return new StringBuilder()
                .append("<ipsec-ikeless ").append(IPSEC_IKELESS_NAMESPACE).append(">")
                .append("<sad>")
                .append("<sad-entry nc:operation=\"delete\">")
                .append("<name>").append(config.getName()).append("_").append(config.getSpi()).append("</name>")
                .append("<reqid>").append(config.getReqId()).append("</reqid>")
                .append("</sad-entry>")
                .append("</sad>")
                .append("</ipsec-ikeless>")
                .toString();
    }

    public static String formatDelSAD(IpsecConfig config, long oldSPI) {
        return new StringBuilder()
                .append("<ipsec-ikeless ").append(IPSEC_IKELESS_NAMESPACE).append(">")
                .append("<sad>")
                .append("<sad-entry nc:operation=\"delete\">")
                .append("<name>").append(config.getName()).append("_").append(oldSPI).append("</name>")
                .append("<reqid>").append(config.getReqId()).append("</reqid>")
                .append("</sad-entry>")
                .append("</sad>")
                .append("</ipsec-ikeless>")
                .toString();
    }

    public static String formatDelSPD(IpsecConfig config) {
        return new StringBuilder()
                .append("<ipsec-ikeless ").append(IPSEC_IKELESS_NAMESPACE).append(">")
                .append("<spd>")
                .append("<spd-entry nc:operation=\"delete\">")
                .append("<name>").append(config.getName()).append("_").append(config.getSpi()).append("</name>")
                .append("<reqid>").append(config.getReqId()).append("</reqid>")
                .append("</spd-entry>")
                .append("</spd>")
                .append("</ipsec-ikeless>")
                .toString();
    }

    public static String generateI2NSFConfig(String[] SADEntries, String[] SPDEntries) {
        StringBuilder result = new StringBuilder();
        result.append("<ipsec-ikeless ").append(IPSEC_IKELESS_NAMESPACE).append(">");
        if (SADEntries[0] != null || SADEntries[1] != null) {
            result.append("<sad>");
            if (SADEntries[0] != null) {
                result.append(SADEntries[0]);
            }
            if (SADEntries[1] != null) {
                result.append(SADEntries[1]);
            }
            result.append("</sad>");
        }

        if (SPDEntries[0] != null || SPDEntries[1] != null) {
            result.append("<spd>");
            if (SPDEntries[0] != null) {
                result.append(SPDEntries[0]);
            }
            if (SPDEntries[1] != null) {
                result.append(SPDEntries[1]);
            }
            result.append("</spd>");
        }
        result.append("</ipsec-ikeless>");
        return result.toString();
    }

}
