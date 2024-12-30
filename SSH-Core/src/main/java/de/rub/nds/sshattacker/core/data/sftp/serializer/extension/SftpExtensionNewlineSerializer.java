/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.serializer.extension;

import static de.rub.nds.modifiablevariable.util.StringUtil.backslashEscapeString;

import de.rub.nds.sshattacker.core.data.sftp.message.extension.SftpExtensionNewline;
import de.rub.nds.sshattacker.core.protocol.common.SerializerStream;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SftpExtensionNewlineSerializer
        extends SftpAbstractExtensionSerializer<SftpExtensionNewline> {

    private static final Logger LOGGER = LogManager.getLogger();

    private static void serializeNewlineSeperator(
            SftpExtensionNewline object, SerializerStream output) {
        Integer newlineSeperatorLength = object.getNewlineSeperatorLength().getValue();
        LOGGER.debug("NewlineSeperator length: {}", newlineSeperatorLength);
        output.appendInt(newlineSeperatorLength);
        String newlineSeperator = object.getNewlineSeperator().getValue();
        LOGGER.debug("NewlineSeperator: {}", () -> backslashEscapeString(newlineSeperator));
        output.appendString(newlineSeperator, StandardCharsets.UTF_8);
    }

    @Override
    protected void serializeExtensionValue(SftpExtensionNewline object, SerializerStream output) {
        serializeNewlineSeperator(object, output);
    }
}
