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
import de.rub.nds.sshattacker.core.protocol.common.SshMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.connection.message.GlobalRequestSuccessMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class GlobalRequestSuccessMessageSerializer
        extends SshMessageSerializer<GlobalRequestSuccessMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private static void serializeResponseSpecificData(
            GlobalRequestSuccessMessage object, SerializerStream output) {
        if (object.getResponseSpecificData() != null) {
            byte[] responseSpecificData = object.getResponseSpecificData().getValue();
            LOGGER.debug(
                    "Response specific data blob: {}",
                    () -> ArrayConverter.bytesToRawHexString(responseSpecificData));
            output.appendBytes(responseSpecificData);
        } else {
            LOGGER.debug("No response specific data blob set");
        }
    }

    @Override
    protected void serializeMessageSpecificContents(
            GlobalRequestSuccessMessage object, SerializerStream output) {
        serializeResponseSpecificData(object, output);
    }
}
