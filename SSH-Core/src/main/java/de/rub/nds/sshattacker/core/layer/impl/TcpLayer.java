/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.layer.impl;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.CharConstants;
import de.rub.nds.sshattacker.core.layer.LayerConfiguration;
import de.rub.nds.sshattacker.core.layer.LayerProcessingResult;
import de.rub.nds.sshattacker.core.layer.ProtocolLayer;
import de.rub.nds.sshattacker.core.layer.constant.ImplementedLayers;
import de.rub.nds.sshattacker.core.layer.context.TcpContext;
import de.rub.nds.sshattacker.core.layer.data.DataContainer;
import de.rub.nds.sshattacker.core.layer.stream.HintedInputStream;
import de.rub.nds.sshattacker.core.layer.stream.HintedInputStreamAdapterStream;
import de.rub.nds.tlsattacker.transport.tcp.TcpTransportHandler;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * The TCP layer is a wrapper around an underlying TCP socket. It forwards the sockets InputStream
 * for reading and sends any data over the TCP socket without modifications.
 */
public class TcpLayer extends ProtocolLayer<DataContainer> {

    private static Logger LOGGER = LogManager.getLogger();

    private final TcpContext context;

    public TcpLayer(TcpContext context) {
        super(ImplementedLayers.TCP);
        this.context = context;
    }

    @Override
    public LayerProcessingResult sendConfiguration() throws IOException {
        LayerConfiguration<DataContainer> configuration = getLayerConfiguration();
        if (configuration != null && configuration.getContainerList() != null) {
            for (DataContainer container : configuration.getContainerList()) {
                // TODO Send container data
            }
        }
        return getLayerResult();
    }

    /** Sends data over the TCP socket. */
    @Override
    public LayerProcessingResult sendData(byte[] data) throws IOException {
        TcpTransportHandler handler = getTransportHandler();
        handler.sendData(data);
        return new LayerProcessingResult(null, getLayerType(), true); // Not implemented
    }

    @Override
    public void receiveMoreData() throws IOException {
        // There is nothing we can do here to fill up our stream, either there is data in it
        // or not
    }

    /** Returns the inputStream associated with the TCP socket. */
    @Override
    public HintedInputStream getDataStream() throws IOException {
        getTransportHandler().setTimeout(getTransportHandler().getTimeout());

        if (context.getContext().getSshContext().isReceiveAsciiModeEnabled()) {
            byte[] receiveBuffer = new byte[0];
            byte[] readByte;
            do {
                readByte = context.getTransportHandler().fetchData(1);
                receiveBuffer = ArrayConverter.concatenate(receiveBuffer, readByte);
            } while (readByte.length > 0 && readByte[0] != CharConstants.NEWLINE);
            currentInputStream =
                    new HintedInputStreamAdapterStream(new ByteArrayInputStream(receiveBuffer));
            return currentInputStream;

        } else {
            currentInputStream =
                    new HintedInputStreamAdapterStream(getTransportHandler().getInputStream());
            return currentInputStream;
        }
    }

    @Override
    public LayerProcessingResult receiveData() {
        return new LayerProcessingResult(null, getLayerType(), true);
    }

    private TcpTransportHandler getTransportHandler() {
        if (context.getTransportHandler() == null) {
            throw new RuntimeException("TransportHandler is not set in context!");
        }
        if (!(context.getTransportHandler() instanceof TcpTransportHandler)) {
            throw new RuntimeException("Trying to set TCP layer with non TCP TransportHandler");
        }
        return (TcpTransportHandler) context.getTransportHandler();
    }
}
