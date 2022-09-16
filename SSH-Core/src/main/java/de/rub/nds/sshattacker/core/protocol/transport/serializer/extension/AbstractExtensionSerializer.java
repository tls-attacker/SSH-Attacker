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
import de.rub.nds.sshattacker.core.protocol.transport.message.extension.AbstractExtension;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class AbstractExtensionSerializer<E extends AbstractExtension>
        extends Serializer<E> {

    private static final Logger LOGGER = LogManager.getLogger();

    protected final E extension;

    public AbstractExtensionSerializer(E extension) {
        this.extension = extension;
    }

    @Override
    protected final void serializeBytes() {
        serializeExtensionName();
        serializeExtensionValueLength();
        serializeExtensionValue();
    }

    private void serializeExtensionName() {
        LOGGER.debug("Extension name length: {}", extension.getNameLength().getValue());
        appendInt(extension.getNameLength().getValue(), DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug("Extension name: {}", extension.getName().getValue());
        appendString(extension.getName().getValue(), StandardCharsets.US_ASCII);
    }

    private void serializeExtensionValueLength() {
        LOGGER.debug("Extension value length: {}", extension.getValueLength().getValue());
        appendInt(extension.getValueLength().getValue(), DataFormatConstants.STRING_SIZE_LENGTH);
    }

    protected abstract void serializeExtensionValue();
}
