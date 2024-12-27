/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.authentication.serializer;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthInfoResponseMessage;
import de.rub.nds.sshattacker.core.protocol.common.SerializerStream;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageSerializer;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class UserAuthInfoResponseMessageSerializer
        extends SshMessageSerializer<UserAuthInfoResponseMessage> {
    private static final Logger LOGGER = LogManager.getLogger();

    private static void serializeResponse(
            UserAuthInfoResponseMessage object, SerializerStream output) {
        Integer responseEntryCount = object.getResponseEntriesCount().getValue();
        LOGGER.debug("Number of response entries: {}", responseEntryCount);
        output.appendInt(responseEntryCount, DataFormatConstants.UINT32_SIZE);

        object.getResponseEntries()
                .forEach(responseEntry -> output.appendBytes(responseEntry.serialize()));
    }

    @Override
    protected void serializeMessageSpecificContents(
            UserAuthInfoResponseMessage object, SerializerStream output) {
        serializeResponse(object, output);
    }
}
