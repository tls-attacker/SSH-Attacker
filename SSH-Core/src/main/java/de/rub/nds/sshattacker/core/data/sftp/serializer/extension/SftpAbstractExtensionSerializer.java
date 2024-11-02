/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.serializer.extension;

import static de.rub.nds.modifiablevariable.util.StringUtil.backslashEscapeString;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.data.sftp.message.extension.SftpAbstractExtension;
import de.rub.nds.sshattacker.core.protocol.common.Serializer;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class SftpAbstractExtensionSerializer<E extends SftpAbstractExtension<E>>
        extends Serializer<E> {

    private static final Logger LOGGER = LogManager.getLogger();

    protected final E extension;

    protected SftpAbstractExtensionSerializer(E extension) {
        super();
        this.extension = extension;
    }

    @Override
    protected final void serializeBytes() {
        serializeExtensionName();
        serializeExtensionValue();
    }

    private void serializeExtensionName() {
        Integer nameLength = extension.getNameLength().getValue();
        LOGGER.debug("Extension name length: {}", nameLength);
        appendInt(nameLength, DataFormatConstants.STRING_SIZE_LENGTH);
        String name = extension.getName().getValue();
        LOGGER.debug("Extension name: {}", () -> backslashEscapeString(name));
        appendString(name, StandardCharsets.US_ASCII);
    }

    protected abstract void serializeExtensionValue();
}
