/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.serializer;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.protocol.connection.message.GlobalRequestOpenSshHostKeysMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class GlobalRequestOpenSshHostKeysMessageSerializer
        extends GlobalRequestMessageSerializer<GlobalRequestOpenSshHostKeysMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public GlobalRequestOpenSshHostKeysMessageSerializer(
            GlobalRequestOpenSshHostKeysMessage message) {
        super(message);
    }

    private void serializeHostKeys() {
        byte[] hostKeys = message.getHostKeys().getValue();
        LOGGER.debug("Host keys blob: {}", () -> ArrayConverter.bytesToRawHexString(hostKeys));
        appendBytes(hostKeys);
    }

    @Override
    protected void serializeMessageSpecificContents() {
        super.serializeMessageSpecificContents();
        serializeHostKeys();
    }
}
