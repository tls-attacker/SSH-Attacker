/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.parser.extension;

import de.rub.nds.sshattacker.core.protocol.transport.message.extension.PingExtension;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class PingExtensionParser extends AbstractExtensionParser<PingExtension> {

    private static final Logger LOGGER = LogManager.getLogger();

    public PingExtensionParser(byte[] array) {
        super(array);
    }

    public PingExtensionParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    protected PingExtension createExtension() {
        return new PingExtension();
    }

    private void parseVersion() {
        int versionLength = parseIntField();
        extension.setVersionLength(versionLength);
        LOGGER.debug("Version length: {}", versionLength);
        String version = parseByteString(versionLength, StandardCharsets.US_ASCII);
        extension.setVersion(version);
        LOGGER.debug("Version: {}", version);
    }

    @Override
    protected void parseExtensionValue() {
        parseVersion();
    }
}
