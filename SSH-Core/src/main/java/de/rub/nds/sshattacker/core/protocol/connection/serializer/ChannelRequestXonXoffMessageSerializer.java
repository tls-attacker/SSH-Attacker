/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.serializer;

import de.rub.nds.sshattacker.core.protocol.common.SerializerStream;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestXonXoffMessage;
import de.rub.nds.sshattacker.core.util.Converter;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ChannelRequestXonXoffMessageSerializer
        extends ChannelRequestMessageSerializer<ChannelRequestXonXoffMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private static void serializeClientFlowControl(
            ChannelRequestXonXoffMessage object, SerializerStream output) {
        Byte clientFlowControl = object.getClientFlowControl().getValue();
        LOGGER.debug(
                "Client can do flow control: {}", () -> Converter.byteToBoolean(clientFlowControl));
        output.appendByte(clientFlowControl);
    }

    @Override
    protected void serializeMessageSpecificContents(
            ChannelRequestXonXoffMessage object, SerializerStream output) {
        super.serializeMessageSpecificContents(object, output);
        serializeClientFlowControl(object, output);
    }
}
