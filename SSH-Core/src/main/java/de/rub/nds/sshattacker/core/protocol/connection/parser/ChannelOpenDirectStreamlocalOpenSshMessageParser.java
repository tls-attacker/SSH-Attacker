/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2025 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.parser;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelOpenDirectStreamlocalOpenSshMessage;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ChannelOpenDirectStreamlocalOpenSshMessageParser
        extends ChannelOpenMessageParser<ChannelOpenDirectStreamlocalOpenSshMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ChannelOpenDirectStreamlocalOpenSshMessageParser(byte[] array) {
        super(array);
    }

    public ChannelOpenDirectStreamlocalOpenSshMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    protected ChannelOpenDirectStreamlocalOpenSshMessage createMessage() {
        return new ChannelOpenDirectStreamlocalOpenSshMessage();
    }

    public void parseSocketPath() {
        message.setSocketPathLength(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        LOGGER.debug("Socket path length: {}", message.getSocketPathLength().getValue());
        message.setSocketPath(
                parseByteString(
                        message.getSocketPathLength().getValue(), StandardCharsets.US_ASCII));
        LOGGER.debug("Socket path: {}", message.getSocketPath().getValue());
    }

    public void parseReservedString() {
        message.setReservedStringLength(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        LOGGER.debug("Reserved string length: {}", message.getReservedStringLength().getValue());
        message.setReservedString(
                parseByteArrayField(message.getReservedStringLength().getValue()));
        LOGGER.debug("Reserved string: {}", message.getReservedString().getValue());
    }

    public void parseReservedUint32() {
        message.setReservedUint32(parseIntField(DataFormatConstants.UINT32_SIZE));
        LOGGER.debug("Reserved uint32: {}", message.getReservedUint32().getValue());
    }

    @Override
    protected void parseMessageSpecificContents() {
        super.parseMessageSpecificContents();
        parseSocketPath();
        parseReservedString();
        parseReservedUint32();
    }
}
