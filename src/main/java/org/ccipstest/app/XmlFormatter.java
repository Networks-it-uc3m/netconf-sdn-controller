package org.ccipstest.app;

import org.slf4j.LoggerFactory;

import java.io.StringReader;
import java.io.StringWriter;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.stream.StreamSource;
public class XmlFormatter {
    public static String formatXml(String xml) {
        try {
            Transformer transformer = TransformerFactory.newInstance().newTransformer();
            transformer.setOutputProperty(OutputKeys.INDENT, "yes");
            transformer.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "2");

            StreamSource xmlInput = new StreamSource(new StringReader(xml));
            StringWriter stringWriter = new StringWriter();
            StreamResult xmlOutput = new StreamResult(stringWriter);
            transformer.transform(xmlInput, xmlOutput);

            return xmlOutput.getWriter().toString();
        } catch (Exception e) {
            // Log error and return original XML if formatting fails
            LoggerFactory.getLogger(XmlFormatter.class).error("Error formatting XML", e);
            return xml;
        }
    }
}