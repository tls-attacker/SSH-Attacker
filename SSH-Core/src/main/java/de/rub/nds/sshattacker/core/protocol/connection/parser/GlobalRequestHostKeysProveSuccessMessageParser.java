/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.parser;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageParser;
import de.rub.nds.sshattacker.core.protocol.connection.message.GlobalRequestHostKeysProveSuccessMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class GlobalRequestHostKeysProveSuccessMessageParser
        extends SshMessageParser<GlobalRequestHostKeysProveSuccessMessage> {
    private static final Logger LOGGER = LogManager.getLogger();

    public GlobalRequestHostKeysProveSuccessMessageParser(byte[] array) {
        super(array);
    }

    public GlobalRequestHostKeysProveSuccessMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    private void parseHostKeySignatures() {
        message.setHostKeySignatures(parseByteArrayField(getBytesLeft()));
        LOGGER.debug(
                "Host key signatures blob: {}",
                ArrayConverter.bytesToRawHexString(message.getHostKeySignatures().getValue()));
    }

    @Override
    public GlobalRequestHostKeysProveSuccessMessage createMessage() {
        return new GlobalRequestHostKeysProveSuccessMessage();
    }

    @Override
    protected void parseMessageSpecificContents() {
        parseHostKeySignatures();
    }
}
