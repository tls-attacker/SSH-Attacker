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
import de.rub.nds.sshattacker.core.data.sftp.message.extension.SftpExtensionWithVersion;
import de.rub.nds.sshattacker.core.protocol.common.SerializerStream;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SftpExtensionWithVersionSerializer<T extends SftpExtensionWithVersion<T>>
        extends SftpAbstractExtensionSerializer<T> {

    private static final Logger LOGGER = LogManager.getLogger();

    private void serializeVersion(T object, SerializerStream output) {
        Integer versionLength = object.getVersionLength().getValue();
        LOGGER.debug("Version length: {}", versionLength);
        output.appendInt(versionLength, DataFormatConstants.STRING_SIZE_LENGTH);
        String version = object.getVersion().getValue();
        LOGGER.debug("Version: {}", () -> backslashEscapeString(version));
        output.appendString(version, StandardCharsets.US_ASCII);
    }

    @Override
    protected void serializeExtensionValue(T object, SerializerStream output) {
        serializeVersion(object, output);
    }
}
