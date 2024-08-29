package org.ccips.app.config;


public class Node {


    private String networkInternal;
    private String ipData;
    private String ipControl;
    private String ipDMZ;


    public Node(String networkInternal, String ipDMZ, String ipData, String ipControl) {
        this.networkInternal = networkInternal;
        this.ipDMZ = ipDMZ;
        this.ipData = ipData;
        this.ipControl = ipControl;
    }

    public String getNetworkInternal() {
        return networkInternal;
    }

    public void setNetworkInternal(String networkInternal) {
        this.networkInternal = networkInternal;
    }

    public String getIpData() {
        return ipData;
    }

    public void setIpData(String ipData) {
        this.ipData = ipData;
    }

    public String getIpControl() {
        return ipControl;
    }

    public void setIpControl(String ipControl) {
        this.ipControl = ipControl;
    }

    public String getIpDMZ() {
        return ipDMZ;
    }

    public void setIpDMZ(String ipDMZ) {
        this.ipDMZ = ipDMZ;
    }
}