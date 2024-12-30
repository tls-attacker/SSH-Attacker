/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.parser.extension;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.data.sftp.message.extension.SftpExtensionUnknown;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SftpExtensionUnknownParser extends SftpAbstractExtensionParser<SftpExtensionUnknown> {

    private static final Logger LOGGER = LogManager.getLogger();

    public SftpExtensionUnknownParser(byte[] array) {
        super(SftpExtensionUnknown::new, array);
    }

    public SftpExtensionUnknownParser(byte[] array, int startPosition) {
        super(SftpExtensionUnknown::new, array, startPosition);
    }

    @Override
    protected void parseExtensionValue() {
        extension.setValueLength(parseIntField());
        extension.setValue(parseArrayOrTillEnd(extension.getValueLength().getValue()));
        LOGGER.debug(
                "Extension value: {}",
                () -> ArrayConverter.bytesToRawHexString(extension.getValue().getValue()));
    }
}
