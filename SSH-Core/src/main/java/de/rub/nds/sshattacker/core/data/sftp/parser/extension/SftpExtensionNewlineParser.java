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
import de.rub.nds.sshattacker.core.data.sftp.message.extension.SftpExtensionNewline;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SftpExtensionNewlineParser extends SftpAbstractExtensionParser<SftpExtensionNewline> {

    private static final Logger LOGGER = LogManager.getLogger();

    public SftpExtensionNewlineParser(byte[] array) {
        super(SftpExtensionNewline::new, array);
    }

    public SftpExtensionNewlineParser(byte[] array, int startPosition) {
        super(SftpExtensionNewline::new, array, startPosition);
    }

    private void parseNewlineSeperator() {
        int newlineSeperatorLength = parseIntField(DataFormatConstants.STRING_SIZE_LENGTH);
        extension.setNewlineSeperatorLength(newlineSeperatorLength);
        LOGGER.debug("NewlineSeperator length: {}", newlineSeperatorLength);
        String newlineSeperator = parseByteString(newlineSeperatorLength, StandardCharsets.UTF_8);
        extension.setNewlineSeperator(newlineSeperator);
        LOGGER.debug("NewlineSeperator: {}", () -> backslashEscapeString(newlineSeperator));
    }

    @Override
    protected void parseExtensionValue() {
        parseNewlineSeperator();
    }
}
