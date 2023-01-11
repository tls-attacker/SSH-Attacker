/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.config;

import de.rub.nds.sshattacker.core.config.filter.ConfigDisplayFilter;
import jakarta.xml.bind.JAXBContext;
import jakarta.xml.bind.JAXBException;
import jakarta.xml.bind.Unmarshaller;
import jakarta.xml.bind.util.JAXBSource;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.stream.StreamResult;

public class ConfigIO {

    /** context initialization is expensive, we need to do that only once */
    private static JAXBContext context;

    static synchronized JAXBContext getJAXBContext() throws JAXBException {
        if (context == null) {
            context = JAXBContext.newInstance(Config.class);
        }
        return context;
    }

    public static void write(Config config, File f) {
        try {
            write(config, new FileOutputStream(f));
        } catch (FileNotFoundException ex) {
            throw new RuntimeException(ex);
        }
    }

    public static void write(final Config config, final OutputStream outputStream) {
        try (ByteArrayOutputStream tempStream = new ByteArrayOutputStream()) {
            // circumvent the max indentation of 8 of the JAXB marshaller
            Transformer transformer = TransformerFactory.newInstance().newTransformer();
            transformer.setOutputProperty(OutputKeys.INDENT, "yes");
            transformer.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "4");
            transformer.transform(
                    new JAXBSource(getJAXBContext(), config), new StreamResult(tempStream));

            // Replace line separators with the system specific line separator
            String xmlText = tempStream.toString();
            xmlText = xmlText.replaceAll("\r?\n", System.lineSeparator());
            outputStream.write(xmlText.getBytes(StandardCharsets.UTF_8));
        } catch (IOException | JAXBException | TransformerException ex) {
            throw new RuntimeException("Could not format XML", ex);
        }
    }

    public static void write(Config config, File f, ConfigDisplayFilter filter) {
        Config filteredConfig = copy(config);
        filter.applyFilter(filteredConfig);
        write(filteredConfig, f);
    }

    public static void write(Config config, OutputStream os, ConfigDisplayFilter filter) {
        Config filteredConfig = copy(config);
        filter.applyFilter(filteredConfig);
        write(filteredConfig, os);
    }

    public static Config read(File f) {
        try {
            Unmarshaller unmarshaller = getJAXBContext().createUnmarshaller();
            // output any anomalies in the given config file
            unmarshaller.setEventHandler(
                    event -> {
                        // Raise an exception also on warnings
                        return false;
                    });
            return read(new FileInputStream(f), unmarshaller);
        } catch (JAXBException e) {
            throw new RuntimeException(e);
        } catch (FileNotFoundException e) {
            throw new IllegalArgumentException("File cannot be found", e);
        }
    }

    public static Config read(InputStream stream) {
        try {
            Unmarshaller unmarshaller = getJAXBContext().createUnmarshaller();
            // output any anomalies in the given config file
            unmarshaller.setEventHandler(
                    event -> {
                        // Raise an exception also on warnings
                        return false;
                    });
            return read(stream, unmarshaller);
        } catch (JAXBException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Reads the XML from the given inputStream with the provided unmarshaller into a new Config
     *
     * @param stream The stream that provides the XML structure
     * @param unmarshaller The unmarshaller that will be used during the parsing
     * @return Config a new Config that contains the parsed values from the inputStream
     */
    private static Config read(InputStream stream, Unmarshaller unmarshaller) {
        if (stream == null) {
            throw new IllegalArgumentException("Stream cannot be null");
        }
        try {
            // TODO: Implement schema validation
            XMLInputFactory xif = XMLInputFactory.newFactory();
            xif.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
            xif.setProperty(XMLInputFactory.SUPPORT_DTD, false);
            XMLStreamReader xsr = xif.createXMLStreamReader(stream);
            return (Config) unmarshaller.unmarshal(xsr);
        } catch (XMLStreamException | JAXBException e) {
            throw new RuntimeException(e);
        }
    }

    public static Config copy(Config config) {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        ConfigIO.write(config, byteArrayOutputStream);
        return ConfigIO.read(new ByteArrayInputStream(byteArrayOutputStream.toByteArray()));
    }

    private ConfigIO() {}
}
