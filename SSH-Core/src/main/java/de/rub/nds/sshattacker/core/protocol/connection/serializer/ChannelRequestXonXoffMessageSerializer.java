/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.serializer;

import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestXonXoffMessage;
import de.rub.nds.sshattacker.core.util.Converter;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ChannelRequestXonXoffMessageSerializer
        extends ChannelRequestMessageSerializer<ChannelRequestXonXoffMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ChannelRequestXonXoffMessageSerializer(ChannelRequestXonXoffMessage message) {
        super(message);
    }

    private void serializeClientFlowControl() {
        LOGGER.debug(
                "Client can do flow control: "
                        + Converter.byteToBoolean(message.getClientFlowControl().getValue()));
        appendByte(message.getClientFlowControl().getValue());
    }

    @Override
    public void serializeMessageSpecificContents() {
        super.serializeMessageSpecificContents();
        serializeClientFlowControl();
    }
}
