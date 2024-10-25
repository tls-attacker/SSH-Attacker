/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.parser.extension;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.layer.data.Parser;
import de.rub.nds.sshattacker.core.protocol.transport.message.extension.AbstractExtension;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class AbstractExtensionParser<E extends AbstractExtension<E>> extends Parser<E> {

    private static final Logger LOGGER = LogManager.getLogger();

    protected final E extension = createExtension();

    protected AbstractExtensionParser(InputStream stream) {
        super(stream);
    }

    /*    protected AbstractExtensionParser(byte[] array) {
        super(array);
    }

    protected AbstractExtensionParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }*/

    protected abstract E createExtension();

    protected void parseExtensionData(E abstractExtension) {
        parseExtensionName(abstractExtension);
        parseExtensionValue(abstractExtension);
    }

    /* @Override
    public final E parse() {
        parseExtensionName();
        parseExtensionValue();
        return extension;
    }*/

    protected void parseExtensionName(E abstractExtension) {
        abstractExtension.setNameLength(parseIntField(DataFormatConstants.UINT32_SIZE));
        LOGGER.debug("Extension name length: {}", extension.getNameLength().getValue());
        abstractExtension.setName(
                parseByteString(extension.getNameLength().getValue(), StandardCharsets.US_ASCII));
        LOGGER.debug("Extension name: {}", extension.getName().getValue());
    }

    protected abstract void parseExtensionValue(E AbstractExtension);
}
