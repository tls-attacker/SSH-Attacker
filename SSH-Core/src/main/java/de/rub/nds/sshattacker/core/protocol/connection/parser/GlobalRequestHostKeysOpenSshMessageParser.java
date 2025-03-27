/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.parser;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.protocol.connection.message.GlobalRequestHostKeysOpenSshMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class GlobalRequestHostKeysOpenSshMessageParser
        extends GlobalRequestMessageParser<GlobalRequestHostKeysOpenSshMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public GlobalRequestHostKeysOpenSshMessageParser(byte[] array) {
        super(array);
    }

    public GlobalRequestHostKeysOpenSshMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    public GlobalRequestHostKeysOpenSshMessage createMessage() {
        return new GlobalRequestHostKeysOpenSshMessage();
    }

    private void parseHostKeys() {
        message.setHostKeys(parseByteArrayField(getBytesLeft()));
        LOGGER.debug(
                "Host keys blob: {}",
                ArrayConverter.bytesToRawHexString(message.getHostKeys().getValue()));
    }

    @Override
    protected void parseMessageSpecificContents() {
        super.parseMessageSpecificContents();
        parseHostKeys();
    }
}
