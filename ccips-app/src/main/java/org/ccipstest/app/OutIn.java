package org.ccipstest.app;

import org.onosproject.netconf.NetconfSession;

public class OutIn {
    private IpsecConfig cfg;
    private NetconfSession s1;
    private NetconfSession s2;
    private String s1_string;
    private String s2_string;

    public OutIn(IpsecConfig cfg, NetconfSession s1, NetconfSession s2, String s1_string, String s2_string) {
        this.cfg = cfg;
        this.s1 = s1;
        this.s2 = s2;
        this.s1_string = s1_string;
        this.s2_string = s2_string;
    }

    public IpsecConfig getCfg() {
        return cfg;
    }

    public void setCfg(IpsecConfig cfg) {
        this.cfg = cfg;
    }

    public NetconfSession getS1() {
        return s1;
    }

    public void setS1(NetconfSession s1) {
        this.s1 = s1;
    }

    public NetconfSession getS2() {
        return s2;
    }

    public void setS2(NetconfSession s2) {
        this.s2 = s2;
    }

    //    @Override
//    public String toString() {
//        return "\nOutIn{" +
//                "cfg=" + cfg +
//                "}";
//    }
    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("----- OutIn Details -----------------------------------------------------------------------\n");
        sb.append("IPsec Configuration: ").append(cfg).append("\n");
        //sb.append("IPsec Configuration").append("\n");//TESTING
        sb.append("Session 1 String: ").append(s1_string).append("\n");
        sb.append("Session 2 String: ").append(s2_string).append("\n");
        sb.append("-------------------------------------------------------------------------------------------\n");
        return sb.toString();
    }

    public String getS1_string() {
        return this.s1_string;
    }

    public void setS1_string(String s1_string) {
        this.s1_string = s1_string;
    }

    public String getS2_string() {
        return this.s2_string;
    }

    public void setS2_string(String s2_string) {
        this.s2_string = s2_string;
    }
}
