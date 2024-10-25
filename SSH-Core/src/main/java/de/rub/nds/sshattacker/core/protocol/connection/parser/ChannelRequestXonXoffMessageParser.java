/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.parser;

import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestXonXoffMessage;
import de.rub.nds.sshattacker.core.util.Converter;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ChannelRequestXonXoffMessageParser
        extends ChannelRequestMessageParser<ChannelRequestXonXoffMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ChannelRequestXonXoffMessageParser(InputStream stream) {
        super(stream);
    }

    @Override
    public void parse(ChannelRequestXonXoffMessage message) {
        parseProtocolMessageContents(message);
    }

    private void parseClientFlowControl(ChannelRequestXonXoffMessage message) {
        message.setClientFlowControl(parseByteField(1));
        LOGGER.debug(
                "Client can do flow control: {}",
                Converter.byteToBoolean(message.getClientFlowControl().getValue()));
    }

    @Override
    protected void parseMessageSpecificContents(ChannelRequestXonXoffMessage message) {
        super.parseMessageSpecificContents(message);
        parseClientFlowControl(message);
    }
}
