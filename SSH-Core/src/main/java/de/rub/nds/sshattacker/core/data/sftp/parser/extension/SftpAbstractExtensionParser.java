/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.parser.extension;

import static de.rub.nds.modifiablevariable.util.StringUtil.backslashEscapeString;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.data.sftp.message.extension.SftpAbstractExtension;
import de.rub.nds.sshattacker.core.protocol.common.Parser;
import java.nio.charset.StandardCharsets;
import java.util.function.Supplier;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class SftpAbstractExtensionParser<E extends SftpAbstractExtension<E>>
        extends Parser<E> {

    private static final Logger LOGGER = LogManager.getLogger();

    protected final E extension;

    protected SftpAbstractExtensionParser(Supplier<E> extensionFactory, byte[] array) {
        super(array);
        extension = extensionFactory.get();
    }

    protected SftpAbstractExtensionParser(
            Supplier<E> extensionFactory, byte[] array, int startPosition) {
        super(array, startPosition);
        extension = extensionFactory.get();
    }

    @Override
    public final E parse() {
        parseExtensionName();
        parseExtensionValue();
        return extension;
    }

    protected void parseExtensionName() {
        extension.setNameLength(parseIntField(DataFormatConstants.UINT32_SIZE));
        LOGGER.debug("Extension name length: {}", extension.getNameLength().getValue());
        extension.setName(
                parseByteString(extension.getNameLength().getValue(), StandardCharsets.US_ASCII));
        LOGGER.debug(
                "Extension name: {}", () -> backslashEscapeString(extension.getName().getValue()));
    }

    protected abstract void parseExtensionValue();
}
