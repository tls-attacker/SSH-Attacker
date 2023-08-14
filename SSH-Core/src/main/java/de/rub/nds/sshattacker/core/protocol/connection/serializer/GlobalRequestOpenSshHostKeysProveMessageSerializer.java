/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.serializer;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.protocol.connection.message.GlobalRequestOpenSshHostKeysProveMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class GlobalRequestOpenSshHostKeysProveMessageSerializer
        extends GlobalRequestMessageSerializer<GlobalRequestOpenSshHostKeysProveMessage> {
    private static final Logger LOGGER = LogManager.getLogger();

    public GlobalRequestOpenSshHostKeysProveMessageSerializer(
            GlobalRequestOpenSshHostKeysProveMessage message) {
        super(message);
    }

    private void serializeHostKeys() {
        LOGGER.debug(
                "Host keys blob: {}",
                ArrayConverter.bytesToRawHexString(message.getHostKeys().getValue()));
        appendBytes(message.getHostKeys().getValue());
    }

    @Override
    public void serializeMessageSpecificContents() {
        super.serializeMessageSpecificContents();
        serializeHostKeys();
    }
}
