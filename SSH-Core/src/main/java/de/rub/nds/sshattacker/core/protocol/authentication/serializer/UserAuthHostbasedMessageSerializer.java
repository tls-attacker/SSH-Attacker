/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.authentication.serializer;

import static de.rub.nds.modifiablevariable.util.StringUtil.backslashEscapeString;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthHostbasedMessage;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class UserAuthHostbasedMessageSerializer
        extends UserAuthRequestMessageSerializer<UserAuthHostbasedMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public UserAuthHostbasedMessageSerializer(UserAuthHostbasedMessage message) {
        super(message);
    }

    private void serializePubKeyAlgorithm() {
        appendInt(
                message.getPubKeyAlgorithmLength().getValue(),
                DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug(
                "Public key algorithm length: " + message.getPubKeyAlgorithmLength().getValue());
        appendString(message.getPubKeyAlgorithm().getValue());
        LOGGER.debug("Public key algorithm: " + message.getPubKeyAlgorithm().getValue());
    }

    private void serializeHostKeyBytes() {
        appendInt(
                message.getHostKeyBytesLength().getValue(), DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug("Host key length: " + message.getHostKeyBytesLength().getValue());
        appendBytes(message.getHostKeyBytes().getValue());
        LOGGER.debug(
                "Host key: "
                        + ArrayConverter.bytesToRawHexString(message.getHostKeyBytes().getValue()));
    }

    private void serializeHostName() {
        appendInt(message.getHostNameLength().getValue(), DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug("Host name length: " + message.getHostNameLength().getValue());
        appendString(message.getHostName().getValue());
        LOGGER.debug("Host name: {}", backslashEscapeString(message.getHostName().getValue()));
    }

    private void serializeClientUserName() {
        appendInt(
                message.getClientUserNameLength().getValue(),
                DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug("Client user name length: " + message.getClientUserNameLength().getValue());
        appendString(message.getClientUserName().getValue(), StandardCharsets.UTF_8);
        LOGGER.debug(
                "Client user name: {}",
                backslashEscapeString(message.getClientUserName().getValue()));
    }

    private void serializeSignature() {
        appendInt(message.getSignatureLength().getValue(), DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug("Signature length: " + message.getSignatureLength().getValue());
        appendBytes(message.getSignature().getValue());
        LOGGER.debug(
                "Signature: "
                        + ArrayConverter.bytesToRawHexString(message.getSignature().getValue()));
    }

    @Override
    public void serializeMessageSpecificContents() {
        super.serializeMessageSpecificContents();
        serializePubKeyAlgorithm();
        serializeHostKeyBytes();
        serializeHostName();
        serializeClientUserName();
        serializeSignature();
    }
}
