/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.workflow;

import de.rub.nds.modifiablevariable.ModifiableVariable;
import de.rub.nds.modifiablevariable.ModificationFilter;
import de.rub.nds.modifiablevariable.VariableModification;
import de.rub.nds.modifiablevariable.util.XMLPrettyPrinter;
import de.rub.nds.sshattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.sshattacker.core.workflow.action.SendAction;
import de.rub.nds.sshattacker.core.workflow.action.SshAction;
import de.rub.nds.sshattacker.core.protocol.message.ProtocolMessage;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import javax.xml.transform.TransformerException;
import javax.xml.xpath.XPathExpressionException;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.xml.sax.SAXException;

public class WorkflowTraceSerializer {

    private static final Logger LOGGER = LogManager.getLogger();

    /**
     * context initialization is expensive, we need to do that only once
     */
    private static JAXBContext context;

    private static synchronized JAXBContext getJAXBContext() throws JAXBException {
        if (context == null) {
            context = JAXBContext.newInstance(WorkflowTrace.class, ProtocolMessage.class, ModificationFilter.class,
                    VariableModification.class, ModifiableVariable.class, SshAction.class, SendAction.class,
                    ReceiveAction.class);
        }
        return context;
    }

    /**
     * Writes a WorkflowTrace to a File
     *
     * @param file
     *            File to which the WorkflowTrace should be written
     * @param trace
     *            WorkflowTrace that should be written
     * @throws FileNotFoundException
     *             Is thrown if the File cannot be found
     * @throws JAXBException
     *             Is thrown if the Object cannot be serialized
     * @throws IOException
     *             Is thrown if the Process doesn't have the rights to write to
     *             the File
     */
    public static void write(File file, WorkflowTrace trace) throws FileNotFoundException, JAXBException, IOException {
        FileOutputStream fos = new FileOutputStream(file);
        WorkflowTraceSerializer.write(fos, trace);
    }

    /**
     * Writes a serialized WorkflowTrace to string.
     *
     * @param trace
     *            WorkflowTrace that should be written
     * @return String containing XML/serialized representation of the
     *         WorkflowTrace
     * @throws JAXBException
     *             Is thrown if the Object cannot be serialized
     * @throws IOException
     *             Is thrown if the Process doesn't have the rights to write to
     *             the File
     */
    public static String write(WorkflowTrace trace) throws JAXBException, IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        WorkflowTraceSerializer.write(bos, trace);
        return bos.toString();
    }

    /**
     * @param outputStream
     *            The OutputStream to which the Trace should be written to
     * @param workflowTrace
     *            The WorkflowTrace that should be written
     * @throws JAXBException
     *             JAXBException if the JAXB reports a problem
     * @throws IOException
     *             If something goes wrong while writing to the stream
     */
    public static void write(OutputStream outputStream, WorkflowTrace workflowTrace) throws JAXBException, IOException {
        context = getJAXBContext();
        Marshaller m = context.createMarshaller();
        m.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
        try (ByteArrayOutputStream tempStream = new ByteArrayOutputStream()) {
            m.marshal(workflowTrace, tempStream);
            try {
                outputStream.write(XMLPrettyPrinter.prettyPrintXML(tempStream.toString()).getBytes());
            } catch (TransformerException | XPathExpressionException | ParserConfigurationException | SAXException ex) {
                throw new RuntimeException("Could not format XML");
            }
        }
        outputStream.close();
    }

    /**
     * @param inputStream
     *            The InputStream from which the Parameter should be read
     * @return The deserialized WorkflowTrace
     * @throws JAXBException
     *             JAXBException if the JAXB reports a problem
     * @throws IOException
     *             If something goes wrong while writing to the stream
     * @throws XMLStreamException
     *             If there is a Problem with the XML Stream
     */
    public static WorkflowTrace read(InputStream inputStream) throws JAXBException, IOException, XMLStreamException {
        context = getJAXBContext();
        Unmarshaller m = context.createUnmarshaller();

        XMLInputFactory xif = XMLInputFactory.newFactory();
        xif.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
        xif.setProperty(XMLInputFactory.SUPPORT_DTD, false);
        XMLStreamReader xsr = xif.createXMLStreamReader(inputStream);

        WorkflowTrace wt = (WorkflowTrace) m.unmarshal(xsr);
        inputStream.close();
        return wt;
    }

    public static List<WorkflowTrace> readFolder(File f) {
        if (f.isDirectory()) {
            ArrayList<WorkflowTrace> list = new ArrayList<>();
            for (File file : Objects.requireNonNull(f.listFiles())) {
                if (file.getName().startsWith(".")) {
                    // We ignore the .gitignore File
                    continue;
                }
                WorkflowTrace trace;
                try {
                    trace = WorkflowTraceSerializer.read(new FileInputStream(file));
                    trace.setName(file.getAbsolutePath());
                    list.add(trace);
                } catch (JAXBException | IOException | XMLStreamException ex) {
                    LOGGER.warn("Could not read " + file.getAbsolutePath() + " from Folder.");
                    LOGGER.debug(ex.getLocalizedMessage(), ex);
                }
            }
            return list;
        } else {
            throw new IllegalArgumentException("Cannot read Folder, because its not a Folder");
        }

    }

    private WorkflowTraceSerializer() {

    }

}
