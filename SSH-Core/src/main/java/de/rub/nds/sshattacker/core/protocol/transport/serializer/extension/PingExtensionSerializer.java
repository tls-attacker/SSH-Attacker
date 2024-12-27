/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.serializer.extension;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.common.SerializerStream;
import de.rub.nds.sshattacker.core.protocol.transport.message.extension.PingExtension;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class PingExtensionSerializer extends AbstractExtensionSerializer<PingExtension> {

    private static final Logger LOGGER = LogManager.getLogger();

    @Override
    protected void serializeExtensionValue(PingExtension object, SerializerStream output) {
        serializeVersionLength(object, output);
        serializeVersion(object, output);
    }

    private static void serializeVersionLength(PingExtension object, SerializerStream output) {
        Integer versionLength = object.getVersionLength().getValue();
        LOGGER.debug("Version length: {}", versionLength);
        output.appendInt(versionLength, DataFormatConstants.STRING_SIZE_LENGTH);
    }

    private static void serializeVersion(PingExtension object, SerializerStream output) {
        LOGGER.debug("Version: {}", object.getVersion().getValue());
        output.appendString(object.getVersion().getValue(), StandardCharsets.US_ASCII);
    }
}
