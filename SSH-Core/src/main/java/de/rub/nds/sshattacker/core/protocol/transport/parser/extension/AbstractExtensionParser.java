/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.parser.extension;

import de.rub.nds.sshattacker.core.protocol.common.Parser;
import de.rub.nds.sshattacker.core.protocol.transport.message.extension.AbstractExtension;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class AbstractExtensionParser<E extends AbstractExtension<E>> extends Parser<E> {

    private static final Logger LOGGER = LogManager.getLogger();

    protected final E extension = createExtension();

    protected AbstractExtensionParser(byte[] array) {
        super(array);
    }

    protected AbstractExtensionParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    protected abstract E createExtension();

    @Override
    public final E parse() {
        parseExtensionName();
        parseExtensionValue();
        return extension;
    }

    protected void parseExtensionName() {
        int nameLength = parseIntField();
        extension.setNameLength(nameLength);
        LOGGER.debug("Extension name length: {}", nameLength);
        String name = parseByteString(nameLength, StandardCharsets.US_ASCII);
        extension.setName(name);
        LOGGER.debug("Extension name: {}", name);
    }

    protected abstract void parseExtensionValue();
}
