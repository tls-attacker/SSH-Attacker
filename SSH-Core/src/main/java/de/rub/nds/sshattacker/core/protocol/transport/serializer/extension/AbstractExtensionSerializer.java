/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.serializer.extension;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.common.Serializer;
import de.rub.nds.sshattacker.core.protocol.common.SerializerStream;
import de.rub.nds.sshattacker.core.protocol.transport.message.extension.AbstractExtension;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class AbstractExtensionSerializer<T extends AbstractExtension<T>>
        extends Serializer<T> {

    private static final Logger LOGGER = LogManager.getLogger();

    @Override
    protected final void serializeBytes(T object, SerializerStream output) {
        serializeExtensionName(object, output);
        serializeExtensionValue(object, output);
    }

    private void serializeExtensionName(T object, SerializerStream output) {
        Integer nameLength = object.getNameLength().getValue();
        LOGGER.debug("Extension name length: {}", nameLength);
        output.appendInt(nameLength, DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug("Extension name: {}", object.getName().getValue());
        output.appendString(object.getName().getValue(), StandardCharsets.US_ASCII);
    }

    protected abstract void serializeExtensionValue(T object, SerializerStream output);
}
