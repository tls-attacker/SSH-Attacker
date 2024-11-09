/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.workflow;

import jakarta.xml.bind.JAXBContext;
import jakarta.xml.bind.JAXBException;
import jakarta.xml.bind.Unmarshaller;
import jakarta.xml.bind.util.JAXBSource;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.stream.StreamResult;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public final class WorkflowTraceSerializer {

    private static final Logger LOGGER = LogManager.getLogger();

    /** context initialization is expensive, we need to do that only once */
    private static JAXBContext context;

    static synchronized JAXBContext getJAXBContext() throws JAXBException {
        if (context == null) {
            context = JAXBContext.newInstance(WorkflowTrace.class);
        }
        return context;
    }

    /**
     * Writes a WorkflowTrace to a File
     *
     * @param file File to which the WorkflowTrace should be written
     * @param workflowTrace WorkflowTrace that should be written
     * @throws FileNotFoundException Is thrown if the File cannot be found
     * @throws JAXBException Is thrown if the Object cannot be serialized
     * @throws IOException Is thrown if the Process doesn't have the rights to write to the File
     */
    public static void write(File file, WorkflowTrace workflowTrace)
            throws FileNotFoundException, JAXBException, IOException {
        try (FileOutputStream fos = new FileOutputStream(file, true)) {
            write(fos, workflowTrace);
        } catch (IOException ex) {
            throw new RuntimeException(ex);
        }
    }

    /**
     * Writes a serialized WorkflowTrace to string.
     *
     * @param workflowTrace WorkflowTrace that should be written
     * @return String containing XML/serialized representation of the WorkflowTrace
     * @throws JAXBException Is thrown if the Object cannot be serialized
     * @throws IOException Is thrown if the Process doesn't have the rights to write to the File
     */
    public static String write(WorkflowTrace workflowTrace) throws JAXBException, IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        write(bos, workflowTrace);
        return bos.toString(StandardCharsets.UTF_8);
    }

    /**
     * @param outputStream The OutputStream to which the Trace should be written to.
     * @param workflowTrace The WorkflowTrace that should be written
     * @throws JAXBException JAXBException if the JAXB reports a problem
     * @throws IOException If something goes wrong while writing to the stream
     */
    public static void write(OutputStream outputStream, WorkflowTrace workflowTrace)
            throws JAXBException, IOException {
        context = getJAXBContext();
        try (ByteArrayOutputStream xmlOutputStream = new ByteArrayOutputStream()) {
            // circumvent the max indentation of 8 of the JAXB marshaller
            Transformer transformer = TransformerFactory.newInstance().newTransformer();
            transformer.setOutputProperty(OutputKeys.INDENT, "yes");
            transformer.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "4");
            transformer.transform(
                    new JAXBSource(context, workflowTrace), new StreamResult(xmlOutputStream));

            String xmlText = xmlOutputStream.toString();
            // Replace line separators with the system specific line separator
            xmlText = xmlText.replaceAll("\r?\n", System.lineSeparator());
            outputStream.write(xmlText.getBytes());
        } catch (TransformerException E) {
            LOGGER.debug(E.getStackTrace());
        }
        outputStream.close();
    }

    /**
     * @param inputStream The InputStream from which the Parameter should be read. Does NOT perform
     *     schema validation
     * @return The deserialized WorkflowTrace
     * @throws JAXBException JAXBException if the JAXB reports a problem
     * @throws IOException If something goes wrong while writing to the stream
     * @throws XMLStreamException If there is a Problem with the XML Stream
     */
    public static WorkflowTrace insecureRead(InputStream inputStream)
            throws JAXBException, IOException, XMLStreamException {
        context = getJAXBContext();
        Unmarshaller unmarshaller = context.createUnmarshaller();
        unmarshaller.setEventHandler(
                event -> {
                    // raise an Exception also on Warnings
                    return false;
                });
        XMLInputFactory xif = XMLInputFactory.newFactory();
        xif.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
        xif.setProperty(XMLInputFactory.SUPPORT_DTD, false);
        XMLStreamReader xsr = xif.createXMLStreamReader(inputStream);
        WorkflowTrace wt = (WorkflowTrace) unmarshaller.unmarshal(xsr);
        inputStream.close();
        return wt;
    }

    /**
     * Read multiple {@code WorkflowTrace} objects from their serialized XML form given the parent
     * directory. WARNING: Does not perform schema validation.
     *
     * @param folder The parent directory containing one or multiple {@code WorkflowTrace} objects
     *     in serialized XML format.
     * @return A list of parsed {@code WorkflowTrace} objects.
     */
    public static List<WorkflowTrace> insecureReadFolder(File folder) {
        if (folder.isDirectory()) {
            ArrayList<WorkflowTrace> list = new ArrayList<>();
            for (File file : Objects.requireNonNull(folder.listFiles())) {
                if (file.getName().startsWith(".")) {
                    // We ignore the .gitignore File
                    continue;
                }
                WorkflowTrace trace;
                try (FileInputStream fis = new FileInputStream(file)) {
                    trace = insecureRead(fis);
                    trace.setName(file.getAbsolutePath());
                    list.add(trace);
                } catch (JAXBException | IOException | XMLStreamException ex) {
                    LOGGER.warn("Could not read {} from Folder.", file.getAbsolutePath());
                    LOGGER.debug(ex.getLocalizedMessage(), ex);
                }
            }
            return list;
        } else {
            throw new IllegalArgumentException("Cannot read Folder, because its not a Folder");
        }
    }

    // TODO: Implement schema validation

    private WorkflowTraceSerializer() {
        super();
    }
}
