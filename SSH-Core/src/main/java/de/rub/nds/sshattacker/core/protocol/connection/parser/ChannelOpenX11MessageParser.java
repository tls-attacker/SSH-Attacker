/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2025 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.parser;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelOpenX11Message;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ChannelOpenX11MessageParser extends ChannelOpenMessageParser<ChannelOpenX11Message> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ChannelOpenX11MessageParser(byte[] array) {
        super(array);
    }

    public ChannelOpenX11MessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    protected ChannelOpenX11Message createMessage() {
        return new ChannelOpenX11Message();
    }

    public void parseOriginatorAddress() {
        message.setOriginatorAddressLength(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        LOGGER.debug(
                "Originator address length: {}", message.getOriginatorAddressLength().getValue());
        message.setOriginatorAddress(
                parseByteString(
                        message.getOriginatorAddressLength().getValue(),
                        StandardCharsets.US_ASCII));
        LOGGER.debug("Originator address: {}", message.getOriginatorAddress().getValue());
    }

    public void parseOriginatorPort() {
        message.setOriginatorPort(parseIntField(DataFormatConstants.UINT32_SIZE));
        LOGGER.debug("Originator port: {}", message.getOriginatorPort().getValue());
    }

    @Override
    protected void parseMessageSpecificContents() {
        super.parseMessageSpecificContents();
        parseOriginatorAddress();
        parseOriginatorPort();
    }
}
