/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.parser;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageParser;
import de.rub.nds.sshattacker.core.protocol.transport.message.PongMessage;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class PongMessageParser extends SshMessageParser<PongMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public PongMessageParser(InputStream stream) {
        super(stream);
    }

    @Override
    public void parse(PongMessage message) {
        parseProtocolMessageContents(message);
    }

    /*    public PongMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }*/

    /*
        @Override
        protected PongMessage createMessage() {
            return new PongMessage();
        }
    */

    @Override
    protected void parseMessageSpecificContents(PongMessage message) {
        message.setDataLength(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        LOGGER.debug("Data length: {}", message.getDataLength().getValue());
        message.setData(parseByteArrayField(message.getDataLength().getValue()));
        LOGGER.debug("Data: {}", ArrayConverter.bytesToRawHexString(message.getData().getValue()));
    }
}
