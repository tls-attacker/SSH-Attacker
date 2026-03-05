/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.serializer;

import de.rub.nds.sshattacker.core.protocol.common.SerializerStream;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.transport.message.ExtensionInfoMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ExtensionInfoMessageSerializer extends SshMessageSerializer<ExtensionInfoMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private static void serializeExtensionCount(
            ExtensionInfoMessage object, SerializerStream output) {
        Integer extensionCount = object.getExtensionCount().getValue();
        LOGGER.debug("Extension count: {}", extensionCount);
        output.appendInt(extensionCount);
    }

    private static void serializeExtensions(ExtensionInfoMessage object, SerializerStream output) {
        object.getExtensions().forEach(extension -> output.appendBytes(extension.serialize()));
    }

    @Override
    protected void serializeMessageSpecificContents(
            ExtensionInfoMessage object, SerializerStream output) {
        serializeExtensionCount(object, output);
        serializeExtensions(object, output);
    }
}
