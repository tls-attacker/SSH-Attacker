/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.serializer;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.transport.message.ExtensionInfoMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ExtensionInfoMessageSerializer extends SshMessageSerializer<ExtensionInfoMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ExtensionInfoMessageSerializer(ExtensionInfoMessage message) {
        super(message);
    }

    private void serializeExtensionCount() {
        appendInt(message.getExtensionCount().getValue(), DataFormatConstants.UINT32_SIZE);
        LOGGER.debug("Extension count: {}", message.getExtensionCount().getValue());
    }

    private void serializeExtensions() {
        message.getExtensions()
                .forEach(
                        extension ->
                                appendBytes(
                                        extension.getHandler(null).getSerializer().serialize()));
    }

    @Override
    public void serializeMessageSpecificContents() {
        serializeExtensionCount();
        serializeExtensions();
    }
}
