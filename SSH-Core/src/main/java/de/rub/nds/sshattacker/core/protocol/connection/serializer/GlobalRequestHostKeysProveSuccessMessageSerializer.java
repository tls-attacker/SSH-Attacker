/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.serializer;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.connection.message.GlobalRequestHostKeysProveSuccessMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class GlobalRequestHostKeysProveSuccessMessageSerializer
        extends SshMessageSerializer<GlobalRequestHostKeysProveSuccessMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public GlobalRequestHostKeysProveSuccessMessageSerializer(
            GlobalRequestHostKeysProveSuccessMessage message) {
        super(message);
    }

    private void serializeHostKeySignatures() {
        LOGGER.debug(
                "Host key signatures blob: {}",
                ArrayConverter.bytesToRawHexString(message.getHostKeySignatures().getValue()));
        appendBytes(message.getHostKeySignatures().getValue());
    }

    @Override
    public void serializeMessageSpecificContents() {
        serializeHostKeySignatures();
    }
}
