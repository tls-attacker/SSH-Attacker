/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.serializer.extension;

import de.rub.nds.sshattacker.core.protocol.common.SerializerStream;
import de.rub.nds.sshattacker.core.protocol.transport.message.extension.PingExtension;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class PingExtensionSerializer extends AbstractExtensionSerializer<PingExtension> {

    private static final Logger LOGGER = LogManager.getLogger();

    @Override
    protected void serializeExtensionValue(PingExtension object, SerializerStream output) {
        serializeVersion(object, output);
    }

    private static void serializeVersion(PingExtension object, SerializerStream output) {
        Integer versionLength = object.getVersionLength().getValue();
        LOGGER.debug("Version length: {}", versionLength);
        output.appendInt(versionLength);
        String version = object.getVersion().getValue();
        LOGGER.debug("Version: {}", version);
        output.appendString(version, StandardCharsets.US_ASCII);
    }
}
