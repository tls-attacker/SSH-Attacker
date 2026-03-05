/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.serializer;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.protocol.common.SerializerStream;
import de.rub.nds.sshattacker.core.protocol.connection.message.GlobalRequestHostKeysOpenSshMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class GlobalRequestHostKeysOpenSshMessageSerializer
        extends GlobalRequestMessageSerializer<GlobalRequestHostKeysOpenSshMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private static void serializeHostKeys(
            GlobalRequestHostKeysOpenSshMessage object, SerializerStream output) {
        byte[] hostKeys = object.getHostKeys().getValue();
        LOGGER.debug("Host keys blob: {}", () -> ArrayConverter.bytesToRawHexString(hostKeys));
        output.appendBytes(hostKeys);
    }

    @Override
    protected void serializeMessageSpecificContents(
            GlobalRequestHostKeysOpenSshMessage object, SerializerStream output) {
        super.serializeMessageSpecificContents(object, output);
        serializeHostKeys(object, output);
    }
}
