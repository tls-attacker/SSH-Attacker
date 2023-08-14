/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.parser;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.protocol.connection.message.GlobalRequestOpenSshHostKeysProveMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class GlobalRequestOpenSshHostKeysProveMessageParser
        extends GlobalRequestMessageParser<GlobalRequestOpenSshHostKeysProveMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public GlobalRequestOpenSshHostKeysProveMessageParser(byte[] array) {
        super(array);
    }

    public GlobalRequestOpenSshHostKeysProveMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    private void parseHostKeys() {
        message.setHostKeys(parseByteArrayField(getBytesLeft()));
        LOGGER.debug(
                "Host keys blob: {}",
                ArrayConverter.bytesToRawHexString(message.getHostKeys().getValue()));
    }

    @Override
    public GlobalRequestOpenSshHostKeysProveMessage createMessage() {
        return new GlobalRequestOpenSshHostKeysProveMessage();
    }

    @Override
    protected void parseMessageSpecificContents() {
        super.parseMessageSpecificContents();
        parseHostKeys();
    }
}
