/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.parser.extension;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.transport.message.extension.PingExtension;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class PingExtensionParser extends AbstractExtensionParser<PingExtension> {

    private static final Logger LOGGER = LogManager.getLogger();

    public PingExtensionParser(InputStream stream) {
        super(stream);
    }

    @Override
    public void parse(PingExtension pingExtension) {
        parseExtensionData(pingExtension);
    }

    @Override
    protected PingExtension createExtension() {
        return new PingExtension();
    }

    @Override
    protected void parseExtensionValue(PingExtension extension) {
        parseVersionLength(extension);
        parseVersion(extension);
    }

    private void parseVersionLength(PingExtension extension) {
        extension.setVersionLength(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        LOGGER.debug("Version length: {}", extension.getVersionLength().getValue());
    }

    private void parseVersion(PingExtension extension) {
        extension.setVersion(parseByteString(extension.getVersionLength().getValue()));
        LOGGER.debug("Version: {}", extension.getVersion().getValue());
    }
}
