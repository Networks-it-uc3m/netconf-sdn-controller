package org.ccipstest.rest;

public class RequestDeleteDTO {
    String reqId;
    String name;

    public RequestDeleteDTO(String reqId, String name) {
        this.reqId = reqId;
        this.name = name;
    }

    public String getReqId() {
        return this.reqId;
    }

    public void setReqId(String reqId) {
        this.reqId = reqId;
    }

    public String getName() {
        return this.name;
    }

    public void setName(String name) {
        this.name = name;
    }
}
