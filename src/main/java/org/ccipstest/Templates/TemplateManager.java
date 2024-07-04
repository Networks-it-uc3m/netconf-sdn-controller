package org.ccipstest.Templates;
import org.ccipstest.app.IpsecConfig;


public class TemplateManager {




    public static String formatG2GSADValues(IpsecConfig config, String localPrefix, String remotePrefix, String local, String remote) {

        return

                        "        <sad-entry>" +
                        "            <name>" + config.getName() + "_" + config.getSpi() + "</name>" +
                        "            <reqid>" + config.getReqId() + "</reqid>" +
                        "            <ipsec-sa-config>" +
                        "                <spi>" + config.getSpi() + "</spi>" +
                        "                <ext-seq-num>" + "true" + "</ext-seq-num>" +
                        "                <seq-overflow>" + "false" + "</seq-overflow>" +
                        "                <traffic-selector>" +
                        "                    <local-prefix>" + localPrefix + "</local-prefix>" +
                        "                    <remote-prefix>" + remotePrefix + "</remote-prefix>" +
                        "                    <inner-protocol>" + "any" + "</inner-protocol>" +
                        "                </traffic-selector>" +
                        "                <protocol-parameters>esp</protocol-parameters>" +
                        "                <mode>tunnel</mode>" +
                        "                <esp-sa>" +
                        "                    <encryption>" +
                        "                        <encryption-algorithm>"+config.getCryptoConfig().getEncAlg().getValue()+"</encryption-algorithm>" +
                        "                        <key>"+ byteArrayToHexString(config.getCryptoConfig().getEncKey()) +"</key>" +
                        "                       <iv>"+ byteArrayToHexString(config.getCryptoConfig().getIv()) + "</iv>" +
                        "                    </encryption>" +
                        "                    <integrity>" +
                        "                        <integrity-algorithm>"+config.getCryptoConfig().getIntAlg().getValue()+"</integrity-algorithm>" +
                        "                        <key>"+ byteArrayToHexString(config.getCryptoConfig().getIntKey())+"</key>" +
                        "                    </integrity>" +
                        "                </esp-sa>" +
                        "                <sa-lifetime-hard>" +
                        "                    <bytes>" + config.getHardLifetime().getnBytes()+ "</bytes>" +
                        "                    <packets>" +config.getHardLifetime().getnPackets()+"</packets>" +
                        "                    <time>" +config.getHardLifetime().getnTime()+ "</time>" +
                        "                    <idle>"+config.getHardLifetime().getnTimeIdle()+"</idle>" +
                        "                </sa-lifetime-hard>" +
                        "                <sa-lifetime-soft>" +
                        "                    <bytes>" + config.getSoftLifetime().getnBytes() + "</bytes>" +
                        "                    <packets>" + config.getSoftLifetime().getnPackets() + "</packets>" +
                        "                    <time>" + config.getSoftLifetime().getnTime() + "</time>" +
                        "                    <idle>" + config.getSoftLifetime().getnTimeIdle() + "</idle>" +
                        "                    <action>replace</action>" +
                        "                </sa-lifetime-soft>" +
                        "                <tunnel>" +
                        "                <local>"+local+"</local>"+
                        "                <remote>"+remote+"</remote>"+
                        "                </tunnel>"+
                        "            </ipsec-sa-config>" +
                        "        </sad-entry>" +
                        "    </sad>";
    }

    public static String formatG2GSPDValues(IpsecConfig config, String localPrefix, String remotePrefix, String local, String remote, String direction) {
        return "<spd-entry>" +
                "    <name>" + config.getName() + "_" + config.getSpi() + "</name>" +
                "    <direction>" + direction + "</direction>" +
                "    <reqid>" + config.getReqId() + "</reqid>" +
                "    <ipsec-policy-config>" +
                "        <anti-replay-window-size>32</anti-replay-window-size>" +
                "        <traffic-selector>" +
                "            <local-prefix>" + localPrefix + "</local-prefix>" +
                "            <remote-prefix>" + remotePrefix + "</remote-prefix>" +
                "            <inner-protocol>any</inner-protocol>" +
                "        </traffic-selector>" +
                "        <processing-info>" +
                "            <action>protect</action>" +
                "            <ipsec-sa-cfg>" +
                "                <ext-seq-num>true</ext-seq-num>" +
                "                <seq-overflow>false</seq-overflow>" +
                "                <mode>tunnel</mode>" +
                "                <protocol-parameters>esp</protocol-parameters>" +
                "                <esp-algorithms>" +
                "                    <integrity>" + config.getCryptoConfig().getIntAlg().getValue() + "</integrity>" +
                "                    <encryption>" +
                "                        <id>1</id>" +
                "                        <algorithm-type>" + config.getCryptoConfig().getEncAlg().getValue() + "</algorithm-type>" +
                "                        <key-length>" + config.getCryptoConfig().getEncKeyLength()*8 + "</key-length>" +
                "                    </encryption>" +
                "                </esp-algorithms>" +
                "            </ipsec-sa-cfg>" +
                "        </processing-info>" +
                "    </ipsec-policy-config>" +
                "</spd-entry>";

    }

    public static String formatH2HSADValues(IpsecConfig config, String localPrefix, String remotePrefix,String local, String remote) {
        return

                        "        <sad-entry>" +
                        "            <name>" + config.getName() + "_" + config.getSpi() + "</name>" +
                        "            <reqid>" + config.getReqId() + "</reqid>" +
                        "            <ipsec-sa-config>" +
                        "                <spi>" + config.getSpi() + "</spi>" +
                        "                <ext-seq-num>" + "true" + "</ext-seq-num>" +
                        "                <seq-overflow>" + "false" + "</seq-overflow>" +
                        "                <traffic-selector>" +
                        "                    <local-prefix>" + localPrefix + "/32</local-prefix>" +
                        "                    <remote-prefix>" + remotePrefix + "/32</remote-prefix>" +
                        "                    <inner-protocol>" + "any" + "</inner-protocol>" +
                        "                </traffic-selector>" +
                        "                <protocol-parameters>esp</protocol-parameters>" +
                        "                <mode>tunnel</mode>" +
                        "                <esp-sa>" +
                        "                    <encryption>" +
                        "                        <encryption-algorithm>3</encryption-algorithm>" +
                        "                        <key>01:23:45:67:89:AB:CE:DF:01:23:45:67:89:AB:CE:DF</key>" +
                        "                       <iv>01:23:45:67:89:AB:CE:DF:01:23:45:67:89:AB:CE:DF</iv>" +
                        "                    </encryption>" +
                        "                    <integrity>" +
                        "                        <integrity-algorithm>2</integrity-algorithm>" +
                        "                        <key>01:23:45:67:89:AB:CE:DF:01:23:45:67:89:AB:CE:DF</key>" +
                        "                    </integrity>" +
                        "                </esp-sa>" +
                        "                <sa-lifetime-hard>" +
                        "                    <bytes>" + config.getHardLifetime().getnBytes()+ "</bytes>" +
                        "                    <packets>" +config.getHardLifetime().getnPackets()+"</packets>" +
                        "                    <time>" +config.getHardLifetime().getnTime()+ "</time>" +
                        "                    <idle>"+config.getHardLifetime().getnTimeIdle()+"</idle>" +
                        "                </sa-lifetime-hard>" +
                        "                <sa-lifetime-soft>" +
                        "                    <bytes>" + config.getSoftLifetime().getnBytes() + "</bytes>" +
                        "                    <packets>" + config.getSoftLifetime().getnPackets() + "</packets>" +
                        "                    <time>" + config.getSoftLifetime().getnTime() + "</time>" +
                        "                    <idle>" + config.getSoftLifetime().getnTimeIdle() + "</idle>" +
                        "                    <action>replace</action>" +
                        "                </sa-lifetime-soft>" +
                                "                <tunnel>" +
                                "                <local>"+local+"</local>"+
                                "                <remote>"+remote+"</remote>"+
                                "                </tunnel>"+
                        "            </ipsec-sa-config>" +
                        "        </sad-entry>";
    }
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
    public static String formatH2HSPDValues(IpsecConfig config, String localPrefix, String remotePrefix, String direction) {
        return "<spd-entry>" +
                "    <name>" + config.getName() + "_" + config.getSpi() + "</name>" +
                "    <direction>" + direction + "</direction>" +
                "    <reqid>" + config.getReqId() + "</reqid>" +
                "    <ipsec-policy-config>" +
                "        <anti-replay-window-size>32</anti-replay-window-size>" +
                "        <traffic-selector>" +
                "            <local-prefix>" + localPrefix + "/32</local-prefix>" +
                "            <remote-prefix>" + remotePrefix + "/32</remote-prefix>" +
                "            <inner-protocol>any</inner-protocol>" +
                "        </traffic-selector>" +
                "        <processing-info>" +
                "            <action>protect</action>" +
                "            <ipsec-sa-cfg>" +
                "                <ext-seq-num>true</ext-seq-num>" +
                "                <seq-overflow>false</seq-overflow>" +
                "                <mode>tunnel</mode>" +
                "                <protocol-parameters>esp</protocol-parameters>" +
                "                <esp-algorithms>" +
                "                    <integrity>2</integrity>" +
                "                    <encryption>" +
                "                        <id>1</id>" +
                "                        <algorithm-type>3</algorithm-type>" +
                "                        <key-length>128</key-length>" +
                "                    </encryption>" +
                "                </esp-algorithms>" +
                "                <tunnel>" +
                "                <local>"+localPrefix+"</local>"+
                "                <remote>"+remotePrefix+"</remote>"+
                "                </tunnel>"+
                "            </ipsec-sa-cfg>" +
                "        </processing-info>" +
                "    </ipsec-policy-config>" +
                "</spd-entry>";

    }

    public static String formatDelSAD(IpsecConfig config) {
        return
                "<ipsec-ikeless xmlns=\"urn:ietf:params:xml:ns:yang:ietf-i2nsf-ikeless\" xmlns:nc=\"urn:ietf:params:xml:ns:netconf:base:1.0\">" +
                        "<sad>" +
                        "<sad-entry nc:operation=\"delete\">" +
                        "    <name>" + config.getName() + "_" + config.getSpi() + "</name>" +
                        "    <reqid>" + config.getReqId() + "</reqid>" +
                        "</sad-entry>" +
                        "</sad>" +
                        "</ipsec-ikeless>";

    }
    public static String formatDelSAD(IpsecConfig config,long oldSPI) {
        return
                "<ipsec-ikeless xmlns=\"urn:ietf:params:xml:ns:yang:ietf-i2nsf-ikeless\" xmlns:nc=\"urn:ietf:params:xml:ns:netconf:base:1.0\">" +
                        "<sad>" +
                        "<sad-entry nc:operation=\"delete\">" +
                        "    <name>" + config.getName() + "_" + oldSPI + "</name>" +
                        "    <reqid>" + config.getReqId() + "</reqid>" +
                        "</sad-entry>" +
                        "</sad>" +
                        "</ipsec-ikeless>";

    }

    public static String formatDelSPD(IpsecConfig config) {
        return
                "<ipsec-ikeless xmlns=\"urn:ietf:params:xml:ns:yang:ietf-i2nsf-ikeless\" xmlns:nc=\"urn:ietf:params:xml:ns:netconf:base:1.0\">" +
                        "<spd>" +
                        "<spd-entry nc:operation=\"delete\">" +
                        "    <name>" + config.getName() + "_" + config.getSpi() + "</name>" +
                        "    <reqid>" + config.getReqId() + "</reqid>" +
                        "</spd-entry>" +
                        "</spd>" +
                        "</ipsec-ikeless>";


    }



    //    public static String generateI2NSFConfig(String[] SADEntries, String[] SPDEntries) {
//
//        return "\n<ipsec-ikeless xmlns=\"urn:ietf:params:xml:ns:yang:ietf-i2nsf-ikeless\" xmlns:nc=\"urn:ietf:params:xml:ns:netconf:base:1.0\">"
//                +"\n<sad>"
//                + SADEntries[0]+SADEntries[1]
//                +"\n</sad>"
//                +"\n<spd>"
//                + SPDEntries[0]+SPDEntries[1]
//                +"\n</spd>"
//                +"\n</ipsec-ikeless>";
//    }
    public static String generateI2NSFConfig(String[] SADEntries, String[] SPDEntries) {
        StringBuilder result = new StringBuilder();

        result.append("<ipsec-ikeless xmlns=\"urn:ietf:params:xml:ns:yang:ietf-i2nsf-ikeless\" xmlns:nc=\"urn:ietf:params:xml:ns:netconf:base:1.0\">");
        if ((SADEntries[1] != null)||(SADEntries[0] != null)) {
            result.append("<sad>");
            if (SADEntries[0] != null) {
                result.append(SADEntries[0]);
            }
            if (SADEntries[1] != null) {
                result.append(SADEntries[1]);
            }
            result.append("</sad>");
        }

        if ((SPDEntries[1] != null)||(SPDEntries[0] != null)) {
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

