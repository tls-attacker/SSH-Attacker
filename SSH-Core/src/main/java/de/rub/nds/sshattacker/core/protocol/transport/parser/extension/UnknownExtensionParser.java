/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.parser.extension;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.transport.message.extension.UnknownExtension;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class UnknownExtensionParser extends AbstractExtensionParser<UnknownExtension> {

    private static final Logger LOGGER = LogManager.getLogger();

    public UnknownExtensionParser(byte[] array) {
        super(array);
    }

    public UnknownExtensionParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    protected UnknownExtension createExtension() {
        return new UnknownExtension();
    }

    @Override
    protected void parseExtensionValue() {
        extension.setValueLength(parseIntField(DataFormatConstants.UINT32_SIZE));
        extension.setValue(parseArrayOrTillEnd(extension.getValueLength().getValue()));
        LOGGER.debug("Extension value: {}", extension.getValue().getValue());
    }
}
