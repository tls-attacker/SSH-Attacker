/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.serializer;

import static de.rub.nds.modifiablevariable.util.StringUtil.backslashEscapeString;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.data.sftp.message.SftpRequestOpenMessage;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SftpRequestOpenMessageSerializer
        extends SftpRequestMessageSerializer<SftpRequestOpenMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public SftpRequestOpenMessageSerializer(SftpRequestOpenMessage message) {
        super(message);
    }

    public void serializeFilename() {
        LOGGER.debug("Filename length: {}", message.getFilenameLength().getValue());
        appendInt(message.getFilenameLength().getValue(), DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug("Filename: {}", () -> backslashEscapeString(message.getFilename().getValue()));
        appendString(message.getFilename().getValue(), StandardCharsets.UTF_8);
    }

    private void serializePFlags() {
        LOGGER.debug("PFlags: {}", message.getPFlags().getValue());
        appendInt(message.getPFlags().getValue(), DataFormatConstants.UINT32_SIZE);
    }

    private void serializeAttributes() {
        appendBytes(message.getAttributes().getHandler(null).getSerializer().serialize());
    }

    @Override
    public void serializeRequestSpecificContents() {
        serializeFilename();
        serializePFlags();
        serializeAttributes();
    }
}
