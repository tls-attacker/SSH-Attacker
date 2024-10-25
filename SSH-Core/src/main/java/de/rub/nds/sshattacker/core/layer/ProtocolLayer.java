/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.layer;

import de.rub.nds.sshattacker.core.exceptions.EndOfStreamException;
import de.rub.nds.sshattacker.core.exceptions.PreparationException;
import de.rub.nds.sshattacker.core.layer.constant.LayerType;
import de.rub.nds.sshattacker.core.layer.context.LayerContext;
import de.rub.nds.sshattacker.core.layer.data.DataContainer;
import de.rub.nds.sshattacker.core.layer.data.Handler;
import de.rub.nds.sshattacker.core.layer.data.Parser;
import de.rub.nds.sshattacker.core.layer.data.Preparator;
import de.rub.nds.sshattacker.core.layer.stream.LayerInputStream;
import java.io.IOException;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Abstracts a message layer (TCP, UDP, IMAP, etc.). Each layer knows of the layer below and above
 * itself. It can send messages using the layer below and forward received messages to the layer
 * above.
 *
 * @param <ContainerT> The kind of messages/Containers this layer is able to send and receive.
 */
public abstract class ProtocolLayer<ContainerT extends DataContainer> {

    private static final Logger LOGGER = LogManager.getLogger();

    private ProtocolLayer<ContainerT> higherLayer;

    private ProtocolLayer<ContainerT> lowerLayer;

    private LayerConfiguration<ContainerT> layerConfiguration;

    private List<ContainerT> producedDataContainers;

    protected LayerInputStream currentInputStream;

    protected LayerInputStream nextInputStream;

    private LayerType layerType;

    private byte[] unreadBytes;

    public ProtocolLayer(LayerType layerType) {
        producedDataContainers = new LinkedList<>();
        this.layerType = layerType;
        this.unreadBytes = new byte[0];
    }

    public ProtocolLayer getHigherLayer() {
        return higherLayer;
    }

    public ProtocolLayer getLowerLayer() {
        return lowerLayer;
    }

    public void setHigherLayer(ProtocolLayer higherLayer) {
        this.higherLayer = higherLayer;
    }

    public void setLowerLayer(ProtocolLayer lowerLayer) {
        this.lowerLayer = lowerLayer;
    }

    public abstract LayerProcessingResult sendConfiguration() throws IOException;

    public abstract LayerProcessingResult sendData(byte[] additionalData) throws IOException;

    public LayerConfiguration<ContainerT> getLayerConfiguration() {
        return layerConfiguration;
    }

    public void setLayerConfiguration(LayerConfiguration layerConfiguration) {
        this.layerConfiguration = layerConfiguration;
    }

    public LayerProcessingResult<ContainerT> getLayerResult() {
        boolean isExecutedAsPlanned = executedAsPlanned();
        return new LayerProcessingResult(
                producedDataContainers, getLayerType(), isExecutedAsPlanned, getUnreadBytes());
    }

    public boolean executedAsPlanned() {
        boolean isExecutedAsPlanned = true;
        if (getLayerConfiguration() != null) {
            isExecutedAsPlanned = getLayerConfiguration().executedAsPlanned(producedDataContainers);
        }
        return isExecutedAsPlanned;
    }

    /** Sets input stream to null if empty. Throws an exception otherwise. */
    public void removeDrainedInputStream() {
        try {
            if (currentInputStream != null && currentInputStream.available() > 0) {
                throw new RuntimeException("Trying to drain a non-empty inputStream");
            } else {
                currentInputStream = null;
            }
        } catch (IOException ex) {
            LOGGER.error("Could not evaluate Stream availability. Removing Stream anyways");
            currentInputStream = null;
        }
    }

    public void clear() {
        producedDataContainers = new LinkedList<>();
        layerConfiguration = null;
        currentInputStream = null;
        nextInputStream = null;
    }

    protected void addProducedContainer(ContainerT container) {
        producedDataContainers.add(container);
    }

    protected boolean containerAlreadyUsedByHigherLayer(ContainerT container) {
        if (producedDataContainers == null) {
            return false;
        }
        // must check for identical references here
        return producedDataContainers.stream()
                .anyMatch(listedContainer -> listedContainer == container);
    }

    /**
     * A receive call which tries to read till either a timeout occurs or the configuration is
     * fullfilled
     *
     * @return LayerProcessingResult Contains information about the execution of the receive action.
     */
    public abstract LayerProcessingResult receiveData();

    /**
     * Tries to fill up the current Stream with more data, if instead unprocessable data (for the
     * calling layer) is produced, the data is instead cached in the next inputstream. It may be
     * that the current input stream is null when this method is called.
     *
     * @throws IOException Some layers might produce IOExceptions when sending or receiving data
     *     over sockets etc.
     */
    public abstract void receiveMoreData() throws IOException;

    /**
     * Returns a datastream from which currently should be read
     *
     * @return The next data stream with data available.
     * @throws IOException Some layers might produce IOExceptions when sending or receiving data
     *     over sockets etc.
     */
    public LayerInputStream getDataStream() throws IOException {
        if (currentInputStream == null) {
            receiveMoreData();
            if (currentInputStream == null) {
                throw new EndOfStreamException(
                        "Could not receive data stream from lower layer, nothing more to receive");
            }
        }
        /*LOGGER.debug("Returned from 'more data', avilable = " + currentInputStream.available());*/
        if (currentInputStream.available() > 0) {
            return currentInputStream;
        } else {
            if (nextInputStream != null) {
                currentInputStream = nextInputStream;
                return currentInputStream;
            } else {
                LOGGER.debug("Trying to get datastream while no data is available");
                // this.receiveMoreDataForHint(null);
                // <--- Testing -->
                receiveMoreData();
                if (currentInputStream.available() > 0) {
                    return currentInputStream;
                } else {
                    throw new EndOfStreamException(
                            "The original data stream does not produce any more data and there is no next datastream");
                }
                /*throw new EndOfStreamException(
                "The original data stream does not produce any more data and there is no next datastream -> returning now");*/
                // return currentInputStream;
            }
        }
    }

    /**
     * Evaluates if more data can be retrieved for parsing immediately, i.e without receiving on the
     * lowest layer.
     *
     * @return true if more data is available in any receive buffer
     */
    public boolean isDataBuffered() {
        try {
            if ((currentInputStream != null && currentInputStream.available() > 0)
                    || nextInputStream != null && nextInputStream.available() > 0) {
                return true;
            } else if (getLowerLayer() != null) {
                return getLowerLayer().isDataBuffered();
            }
            return false;
        } catch (IOException e) {
            // with exceptions on reading our inputStreams we can not read more data
            LOGGER.error("No more data can be read from the inputStreams with Exception: ", e);
            return false;
        }
    }

    public boolean shouldContinueProcessing() {
        if (layerConfiguration != null) {
            if (layerConfiguration instanceof GenericReceiveLayerConfiguration) {
                // stop collecting more containers, if already got one
                if (!layerConfiguration.getContainerList().isEmpty()) {
                    return false;
                } else {
                    return true;
                }

            } else {
                return layerConfiguration.successRequiresMoreContainers(
                                getLayerResult().getUsedContainers())
                        || isDataBuffered()
                                && ((ReceiveLayerConfiguration) layerConfiguration)
                                        .isProcessTrailingContainers();
            }
        } else {
            return isDataBuffered();
        }
    }

    public LayerType getLayerType() {
        return layerType;
    }

    /**
     * Parses and handles content from a container.
     *
     * @param container The container to handle.
     * @param context The context of the connection. Keeps parsed and handled values.
     */
    protected void readDataContainer(ContainerT container, LayerContext context) {
        LayerInputStream inputStream;
        try {
            inputStream = getLowerLayer().getDataStream();
        } catch (IOException e) {
            LOGGER.warn("The lower layer did not produce a data stream: ", e);
            return;
        }

        Parser parser = container.getParser(context, inputStream);

        try {
            parser.parse(container);
            Handler handler = container.getHandler(context);
            handler.adjustContext(container);
            addProducedContainer(container);
        } catch (RuntimeException ex) {
            unreadBytes = parser.getAlreadyParsed();
        }
    }

    protected void readContainerFromStream(
            ContainerT container, LayerContext context, LayerInputStream inputStream) {

        Parser parser = container.getParser(context, inputStream);
        try {
            parser.parse(container);
            Handler handler = container.getHandler(context);
            handler.adjustContext(container);
            addProducedContainer(container);
        } catch (RuntimeException ex) {
            unreadBytes = parser.getAlreadyParsed();
        }
    }

    public byte[] getUnreadBytes() {
        return unreadBytes;
    }

    public void setUnreadBytes(byte[] unreadBytes) {
        this.unreadBytes = unreadBytes;
    }

    public boolean prepareDataContainer(DataContainer dataContainer, LayerContext context) {
        Preparator preparator = dataContainer.getPreparator(context);
        try {
            preparator.prepare();
            preparator.afterPrepare();
        } catch (PreparationException ex) {
            LOGGER.error(
                    "Could not prepare message " + dataContainer + ". Therefore, we skip it: ", ex);
            return false;
        }
        return true;
    }
}
