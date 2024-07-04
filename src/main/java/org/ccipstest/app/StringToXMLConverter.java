package org.ccipstest.app;

import org.w3c.dom.Document;
import org.w3c.dom.NodeList;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml. transform. TransformerFactory;
import javax.xml. transform.dom.DOMSource;
import javax.xml.transform.stream. StreamResult;
import java.io.ByteArrayInputStream;
import java.io.StringWriter;

public class StringToXMLConverter {

    public static String converter(String inputString) throws TransformerConfigurationException {


        try {

            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            DocumentBuilder builder = factory.newDocumentBuilder();

            Document document = builder.parse(new ByteArrayInputStream(inputString.getBytes()));
            String xmlOutput = documentToString(document);


            NodeList nodelist = document.getElementsByTagName("ipsec-sa-name");
            if(nodelist.getLength()>0){
                return nodelist.item(0).getTextContent();
            }else {
                System.out.println("Debug: No sadb-expire");
                return null;
            }

        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }

    }

    private static String documentToString (Document document) throws Exception {
// Use a Transformer to convert Document to String
        TransformerFactory transformerFactory = TransformerFactory.newInstance();
        Transformer transformer = transformerFactory.newTransformer();
        DOMSource domSource = new DOMSource(document);
        StringWriter writer = new StringWriter();
        StreamResult result = new StreamResult(writer);
        transformer.transform(domSource, result);

        return writer.toString();
    }
}
