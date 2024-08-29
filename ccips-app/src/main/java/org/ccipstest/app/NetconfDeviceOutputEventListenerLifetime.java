package org.ccipstest.app;

import org.onosproject.netconf.NetconfDeviceOutputEvent;
import org.onosproject.netconf.NetconfDeviceOutputEventListener;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import java.io.StringReader;
import java.util.Objects;
import java.util.concurrent.Semaphore;

public class NetconfDeviceOutputEventListenerLifetime implements NetconfDeviceOutputEventListener {
    private final Logger log = LoggerFactory.getLogger(NetconfDeviceOutputEventListenerLifetime.class);
    private static final Semaphore semaphore = new Semaphore(1);

    @Override
    public void event(NetconfDeviceOutputEvent event) {
        new Thread(() -> {
            try {
                String netconfMessage = event.getMessagePayload();

                if (isRelevantNotification(netconfMessage)) {
                    String ipsecSaName = extractIpsecSaName(netconfMessage);
                    semaphore.acquire();
                    try {
                        processEvent(ipsecSaName);
                    } finally {
                        semaphore.release();
                    }
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                log.error("Thread was interrupted", e);
            }
        }).start();
    }

    private void processEvent(String ipsecSaName) {
        try {
            StorageHandler.rekey(ipsecSaName);
        } catch (Exception e) {
            log.error("Error processing NETCONF event", e);
        }
    }

    private boolean isRelevantNotification(String notification) {
        return notification.contains("<soft-lifetime-expire>true</soft-lifetime-expire>");
    }

    public static String extractIpsecSaName(String notification) {

        String startTag = "<ipsec-sa-name>";
        String endTag = "</ipsec-sa-name>";

        int startIndex = notification.indexOf(startTag);
        int endIndex = notification.indexOf(endTag);


        if (startIndex != -1 && endIndex != -1) {
            startIndex += startTag.length();
            return notification.substring(startIndex, endIndex);
        }

        return null;
    }


}

/** <notification
 xmlns="urn:ietf:params:xml:ns:netconf:notification:1.0">
 <eventTime>2023-02-21T10:26:07Z</eventTime>
 <sadb-expire
 xmlns="urn:ietf:params:xml:ns:yang:ietf-i2nsf-ikeless">
 <ipsec-sa-name>out/192.168.201.254/192.168.202.254</ipsec-sa-name>
 <soft-lifetime-expire>true</soft-lifetime-expire>
 </sadb-expire>
 </notification>
 */