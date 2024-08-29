package org.ccipstest.app;

import java.util.Arrays;

public class request {
    Node[] Nodes ;

    String encAlg;
    String authAlg;
    LifetimeConfig softLifetime;;
    LifetimeConfig hardLifetime;

    @Override
    public String toString() {
        return "request{" +
                "Nodes=" + Arrays.toString(Nodes) +
                ", encAlg=" + encAlg +
                ", authAlg=" + authAlg +
                ", softLifetime=" + softLifetime +
                ", hardLifetime=" + hardLifetime +
                '}';
    }

    public request(Node[] nodes, String encAlg, String authAlg, LifetimeConfig softLifetime, LifetimeConfig hardLifetime) {
        this.Nodes = nodes;
        this.encAlg = encAlg;
        this.authAlg = authAlg;
        this.softLifetime=softLifetime;
        this.hardLifetime=hardLifetime;
    }

    public Node[] getNodes() {
        return this.Nodes;
    }

    public void setNodes(Node[] nodes) {
        this.Nodes = nodes;
    }

    public Node getNode1() {
        return this.Nodes[0];
    }

    // Getter for the second node
    public Node getNode2() {
        return this.Nodes[1];
    }

    public String getEncAlg() {
        return this.encAlg;
    }

    public void setEncAlg(String encAlg) {
        this.encAlg = encAlg;
    }

    public String getIntAlg() {
        return this.authAlg;
    }

    public void setIntAlg(String authAlg) {
        this.authAlg = authAlg;
    }

    public LifetimeConfig getSoftLifetime() {
        return softLifetime;
    }

    public void setSoftLifetime(LifetimeConfig softLifetime) {
        this.softLifetime = softLifetime;
    }

    public LifetimeConfig getHardLifetime() {
        return hardLifetime;
    }

    public void setHardLifetime(LifetimeConfig hardLifetime) {
        this.hardLifetime = hardLifetime;
    }
}