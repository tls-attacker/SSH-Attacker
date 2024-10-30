/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.parser;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.protocol.connection.message.GlobalRequestOpenSshHostKeysMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class GlobalRequestOpenSshHostKeysMessageParser
        extends GlobalRequestMessageParser<GlobalRequestOpenSshHostKeysMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public GlobalRequestOpenSshHostKeysMessageParser(byte[] array) {
        super(array);
    }

    public GlobalRequestOpenSshHostKeysMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    private void parseHostKeys() {
        message.setHostKeys(parseByteArrayField(getBytesLeft()));
        LOGGER.debug(
                "Host keys blob: {}",
                () -> ArrayConverter.bytesToRawHexString(message.getHostKeys().getValue()));
    }

    @Override
    public GlobalRequestOpenSshHostKeysMessage createMessage() {
        return new GlobalRequestOpenSshHostKeysMessage();
    }

    @Override
    protected void parseMessageSpecificContents() {
        super.parseMessageSpecificContents();
        parseHostKeys();
    }
}
