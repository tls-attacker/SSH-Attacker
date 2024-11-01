/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.serializer.extended;

import static de.rub.nds.modifiablevariable.util.StringUtil.backslashEscapeString;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.data.sftp.message.extended.SftpRequestExtendedMessage;
import de.rub.nds.sshattacker.core.data.sftp.serializer.request.SftpRequestMessageSerializer;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class SftpRequestExtendedMessageSerializer<T extends SftpRequestExtendedMessage<T>>
        extends SftpRequestMessageSerializer<T> {

    private static final Logger LOGGER = LogManager.getLogger();

    protected SftpRequestExtendedMessageSerializer(T message) {
        super(message);
    }

    private void serializeExtendedRequestName() {
        LOGGER.debug(
                "ExtendedRequestName length: {}",
                message.getExtendedRequestNameLength().getValue());
        appendInt(
                message.getExtendedRequestNameLength().getValue(),
                DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug(
                "ExtendedRequestName: {}",
                () -> backslashEscapeString(message.getExtendedRequestName().getValue()));
        appendString(message.getExtendedRequestName().getValue(), StandardCharsets.US_ASCII);
    }

    @Override
    protected void serializeRequestSpecificContents() {
        serializeExtendedRequestName();
        serializeRequestExtendedSpecificContents();
    }

    protected abstract void serializeRequestExtendedSpecificContents();
}
