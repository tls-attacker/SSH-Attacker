/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.serializer.extension;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.transport.message.extension.PingExtension;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class PingExtensionSerializer extends AbstractExtensionSerializer<PingExtension> {

    private static final Logger LOGGER = LogManager.getLogger();

    public PingExtensionSerializer(PingExtension extension) {
        super(extension);
    }

    @Override
    protected void serializeExtensionValue() {
        serializeVersionLength();
        serializeVersion();
    }

    private void serializeVersionLength() {
        LOGGER.debug("Version length: {}", extension.getVersionLength().getValue());
        appendInt(extension.getVersionLength().getValue(), DataFormatConstants.STRING_SIZE_LENGTH);
    }

    private void serializeVersion() {
        LOGGER.debug("Version: {}", extension.getVersion().getValue());
        appendString(extension.getVersion().getValue(), StandardCharsets.US_ASCII);
    }
}
