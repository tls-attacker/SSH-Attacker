/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.serializer;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.constants.Extension;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.transport.message.ExtensionInfoMessage;
import de.rub.nds.sshattacker.core.protocol.transport.message.extension.AbstractExtension;
import de.rub.nds.sshattacker.core.protocol.transport.serializer.extension.AbstractExtensionSerializer;
import de.rub.nds.sshattacker.core.protocol.transport.serializer.extension.DelayCompressionExtensionSerializer;
import de.rub.nds.sshattacker.core.protocol.transport.serializer.extension.ServerSigAlgsExtensionSerializer;
import de.rub.nds.sshattacker.core.protocol.transport.serializer.extension.UnknownExtensionSerializer;
import java.util.List;
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
        List<AbstractExtension<?>> extensions = message.getExtensions();
        for (int extensionIndex = 0;
                extensionIndex < message.getExtensionCount().getValue();
                extensionIndex++) {
            // determine extension for serializer
            Extension extension =
                    Extension.fromName(extensions.get(extensionIndex).getName().getValue());
            // serialization for each individual extension
            AbstractExtensionSerializer<?> extensionSerializer;
            switch (extension) {
                case SERVER_SIG_ALGS:
                    extensionSerializer =
                            (ServerSigAlgsExtensionSerializer)
                                    extensions.get(extensionIndex).getHandler(null).getSerializer();
                    break;
                case DELAY_COMPRESSION:
                    extensionSerializer =
                            (DelayCompressionExtensionSerializer)
                                    extensions.get(extensionIndex).getHandler(null).getSerializer();
                    break;
                default:
                    LOGGER.debug(
                            "Extension [{}] (index {}) is unknown or not implemented, serializing as UnknownExtension",
                            extension,
                            extensionIndex);
                    extensionSerializer =
                            (UnknownExtensionSerializer)
                                    extensions.get(extensionIndex).getHandler(null).getSerializer();
                    break;
            }
            appendBytes(extensionSerializer.serialize());
        }
    }

    @Override
    public void serializeMessageSpecificContents() {
        serializeExtensionCount();
        serializeExtensions();
    }
}
