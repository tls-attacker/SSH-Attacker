/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.parser.extension;

import static de.rub.nds.modifiablevariable.util.StringUtil.backslashEscapeString;

import de.rub.nds.sshattacker.core.data.sftp.message.extension.SftpExtensionWithVersion;
import java.nio.charset.StandardCharsets;
import java.util.function.Supplier;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SftpExtensionWithVersionParser<T extends SftpExtensionWithVersion<T>>
        extends SftpAbstractExtensionParser<T> {

    private static final Logger LOGGER = LogManager.getLogger();

    public SftpExtensionWithVersionParser(Supplier<T> extensionFactory, byte[] array) {
        super(extensionFactory, array);
    }

    public SftpExtensionWithVersionParser(
            Supplier<T> extensionFactory, byte[] array, int startPosition) {
        super(extensionFactory, array, startPosition);
    }

    private void parseVersion() {
        int versionLength = parseIntField();
        extension.setVersionLength(versionLength);
        LOGGER.debug("Version length: {}", versionLength);
        String version = parseByteString(versionLength, StandardCharsets.US_ASCII);
        extension.setVersion(version);
        LOGGER.debug("Version: {}", () -> backslashEscapeString(version));
    }

    @Override
    protected void parseExtensionValue() {
        parseVersion();
    }
}
