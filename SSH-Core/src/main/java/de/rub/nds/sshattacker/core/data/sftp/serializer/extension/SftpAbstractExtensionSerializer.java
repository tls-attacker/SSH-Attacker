/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.serializer.extension;

import static de.rub.nds.modifiablevariable.util.StringUtil.backslashEscapeString;

import de.rub.nds.sshattacker.core.data.sftp.message.extension.SftpAbstractExtension;
import de.rub.nds.sshattacker.core.protocol.common.Serializer;
import de.rub.nds.sshattacker.core.protocol.common.SerializerStream;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class SftpAbstractExtensionSerializer<T extends SftpAbstractExtension<T>>
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
        output.appendInt(nameLength);
        String name = object.getName().getValue();
        LOGGER.debug("Extension name: {}", () -> backslashEscapeString(name));
        output.appendString(name, StandardCharsets.US_ASCII);
    }

    protected abstract void serializeExtensionValue(T object, SerializerStream output);
}
