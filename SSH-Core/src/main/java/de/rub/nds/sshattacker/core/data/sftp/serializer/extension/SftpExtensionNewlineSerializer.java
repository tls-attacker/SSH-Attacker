/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.serializer.extension;

import static de.rub.nds.modifiablevariable.util.StringUtil.backslashEscapeString;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.data.sftp.message.extension.SftpExtensionNewline;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SftpExtensionNewlineSerializer
        extends SftpAbstractExtensionSerializer<SftpExtensionNewline> {

    private static final Logger LOGGER = LogManager.getLogger();

    public SftpExtensionNewlineSerializer(SftpExtensionNewline extension) {
        super(extension);
    }

    private void serializeNewlineSeperator() {
        Integer newlineSeperatorLength = extension.getNewlineSeperatorLength().getValue();
        LOGGER.debug("NewlineSeperator length: {}", newlineSeperatorLength);
        appendInt(newlineSeperatorLength, DataFormatConstants.STRING_SIZE_LENGTH);
        String newlineSeperator = extension.getNewlineSeperator().getValue();
        LOGGER.debug("NewlineSeperator: {}", () -> backslashEscapeString(newlineSeperator));
        appendString(newlineSeperator, StandardCharsets.UTF_8);
    }

    @Override
    protected void serializeExtensionValue() {
        serializeNewlineSeperator();
    }
}
