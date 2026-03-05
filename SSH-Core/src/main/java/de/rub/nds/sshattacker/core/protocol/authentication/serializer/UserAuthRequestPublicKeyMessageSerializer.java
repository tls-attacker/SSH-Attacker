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
import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthRequestPublicKeyMessage;
import de.rub.nds.sshattacker.core.protocol.common.SerializerStream;
import de.rub.nds.sshattacker.core.util.Converter;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class UserAuthRequestPublicKeyMessageSerializer
        extends UserAuthRequestMessageSerializer<UserAuthRequestPublicKeyMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private static void serializeIncludesSignature(
            UserAuthRequestPublicKeyMessage object, SerializerStream output) {
        LOGGER.debug(
                "Includes signature: {}",
                Converter.byteToBoolean(object.getIncludesSignature().getValue()));
        output.appendByte(object.getIncludesSignature().getValue());
    }

    private static void serializePublicKeyAlgorithmName(
            UserAuthRequestPublicKeyMessage object, SerializerStream output) {
        LOGGER.debug(
                "Public key algorithm name length: {}",
                object.getPublicKeyAlgorithmNameLength().getValue());
        output.appendInt(object.getPublicKeyAlgorithmNameLength().getValue());
        LOGGER.debug(
                "Public key algorithm name: {}",
                () -> backslashEscapeString(object.getPublicKeyAlgorithmName().getValue()));
        output.appendString(
                object.getPublicKeyAlgorithmName().getValue(), StandardCharsets.US_ASCII);
    }

    private static void serializePublicKeyBlob(
            UserAuthRequestPublicKeyMessage object, SerializerStream output) {
        LOGGER.debug("Public key blob length: {}", object.getPublicKeyBlobLength().getValue());
        output.appendInt(object.getPublicKeyBlobLength().getValue());
        LOGGER.debug(
                "Public key blob: {}",
                () -> ArrayConverter.bytesToRawHexString(object.getPublicKeyBlob().getValue()));
        output.appendBytes(object.getPublicKeyBlob().getValue());
    }

    private static void serializeSignature(
            UserAuthRequestPublicKeyMessage object, SerializerStream output) {
        LOGGER.debug("Signature length: {}", object.getSignatureLength().getValue());
        output.appendInt(object.getSignatureLength().getValue());
        LOGGER.debug(
                "Signature: {}",
                () -> ArrayConverter.bytesToRawHexString(object.getSignature().getValue()));
        output.appendBytes(object.getSignature().getValue());
    }

    @Override
    protected void serializeMessageSpecificContents(
            UserAuthRequestPublicKeyMessage object, SerializerStream output) {
        super.serializeMessageSpecificContents(object, output);
        serializeIncludesSignature(object, output);
        serializePublicKeyAlgorithmName(object, output);
        serializePublicKeyBlob(object, output);
        if (Converter.byteToBoolean(object.getIncludesSignature().getValue())) {
            serializeSignature(object, output);
        }
    }
}
