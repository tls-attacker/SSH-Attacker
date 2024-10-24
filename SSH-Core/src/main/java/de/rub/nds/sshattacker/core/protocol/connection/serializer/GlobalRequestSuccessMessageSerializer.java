/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.serializer;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.connection.message.GlobalRequestSuccessMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class GlobalRequestSuccessMessageSerializer
        extends SshMessageSerializer<GlobalRequestSuccessMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public GlobalRequestSuccessMessageSerializer(GlobalRequestSuccessMessage message) {
        super(message);
    }

    private void serializeResponseSpecificData() {
        LOGGER.debug(
                "Response specific data blob: {}",
                ArrayConverter.bytesToRawHexString(message.getResponseSpecificData().getValue()));
        appendBytes(message.getResponseSpecificData().getValue());
    }

    @Override
    public void serializeMessageSpecificContents() {
        serializeResponseSpecificData();
    }
}
