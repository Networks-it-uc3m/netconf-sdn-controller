package org.ccips.app.config;

public class LifetimeConfig {
    public String nBytes;
    public String nPackets;
    public String nTime;
    public String nTimeIdle;

    public LifetimeConfig(String nBytes, String nPackets, String nTime, String nTimeIdle) {
        this.nBytes = nBytes;
        this.nPackets = nPackets;
        this.nTime = nTime;
        this.nTimeIdle = nTimeIdle;
    }

    public String getnTimeIdle() {
        return nTimeIdle;
    }
    public String getnBytes() {
        return nBytes;
    }
    public String getnPackets() {
        return nPackets;
    }
    public String getnTime() {
        return nTime;
    }



    @Override
    public String toString() {
        return "LifetimeConfig{" +
                "nBytes='" + nBytes + '\'' +
                ", nPackets='" + nPackets + '\'' +
                ", nTime='" + nTime + '\'' +
                ", nTimeIdle='" + nTimeIdle + '\'' +
                '}';
    }
}
