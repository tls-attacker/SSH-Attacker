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
import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthRequestPublicKeyMessage;
import de.rub.nds.sshattacker.core.util.Converter;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class UserAuthRequestPublicKeyMessageSerializer
        extends UserAuthRequestMessageSerializer<UserAuthRequestPublicKeyMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public UserAuthRequestPublicKeyMessageSerializer(UserAuthRequestPublicKeyMessage message) {
        super(message);
    }

    private void serializeIncludesSignature() {
        LOGGER.debug(
                "Includes signature: {}",
                Converter.byteToBoolean(message.getIncludesSignature().getValue()));
        appendByte(message.getIncludesSignature().getValue());
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

    private void serializeSignature() {
        LOGGER.debug("Signature length: {}", message.getSignatureLength().getValue());
        appendInt(message.getSignatureLength().getValue(), DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug(
                "Signature: {}",
                ArrayConverter.bytesToRawHexString(message.getSignature().getValue()));
        appendBytes(message.getSignature().getValue());
    }

    @Override
    public void serializeMessageSpecificContents() {
        super.serializeMessageSpecificContents();
        serializeIncludesSignature();
        serializePublicKeyAlgorithmName();
        serializePublicKeyBlob();
        if (Converter.byteToBoolean(message.getIncludesSignature().getValue())) {
            serializeSignature();
        }
    }
}
