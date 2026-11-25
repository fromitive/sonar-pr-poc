package com.example;

import java.io.InputStream;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;

public class XmlParser {

    public Document parse(InputStream in) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance(); // XXE (java:S2755)
        DocumentBuilder builder = factory.newDocumentBuilder();
        return builder.parse(in);
    }
}