/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.parser;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageParser;
import de.rub.nds.sshattacker.core.protocol.transport.message.IgnoreMessage;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class IgnoreMessageParser extends SshMessageParser<IgnoreMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public IgnoreMessageParser(InputStream stream) {
        super(stream);
    }

    private void parseData(IgnoreMessage message) {
        message.setDataLength(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        LOGGER.debug("Data length: {}", message.getDataLength().getValue());
        message.setData(parseByteArrayField(message.getDataLength().getValue()));
        LOGGER.debug("Data: {}", ArrayConverter.bytesToRawHexString(message.getData().getValue()));
    }

    @Override
    protected void parseMessageSpecificContents(IgnoreMessage message) {
        parseData(message);
    }

    @Override
    public void parse(IgnoreMessage message) {
        parseProtocolMessageContents(message);
    }
}
