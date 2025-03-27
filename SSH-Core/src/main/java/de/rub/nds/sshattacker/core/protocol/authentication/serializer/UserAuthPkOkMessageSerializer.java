/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2025 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.authentication.serializer;

import static de.rub.nds.modifiablevariable.util.StringUtil.backslashEscapeString;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthPkOkMessage;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageSerializer;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class UserAuthPkOkMessageSerializer extends SshMessageSerializer<UserAuthPkOkMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public UserAuthPkOkMessageSerializer(UserAuthPkOkMessage message) {
        super(message);
    }

    private void serializePublicKeyAlgorithmName() {
        LOGGER.debug(
                "Public key algorithm name length: {}",
                message.getPublicKeyAlgorithmNameLength().getValue());
        appendInt(
                message.getPublicKeyAlgorithmNameLength().getValue(),
                DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug(
                "Public key algorithm name: {}",
                backslashEscapeString(message.getPublicKeyAlgorithmName().getValue()));
        appendString(message.getPublicKeyAlgorithmName().getValue(), StandardCharsets.US_ASCII);
    }

    private void serializePublicKeyBlob() {
        LOGGER.debug("Public key blob length: {}", message.getPublicKeyBlobLength().getValue());
        appendInt(
                message.getPublicKeyBlobLength().getValue(),
                DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug(
                "Public key blob: {}",
                ArrayConverter.bytesToRawHexString(message.getPublicKeyBlob().getValue()));
        appendBytes(message.getPublicKeyBlob().getValue());
    }

    @Override
    public void serializeMessageSpecificContents() {
        serializePublicKeyAlgorithmName();
        serializePublicKeyBlob();
    }
}
