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
import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthRequestPublicKeyHostboundOpenSshMessage;
import de.rub.nds.sshattacker.core.protocol.common.SerializerStream;
import de.rub.nds.sshattacker.core.util.Converter;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class UserAuthRequestPublicKeyHostboundOpenSshMessageSerializer
        extends UserAuthRequestMessageSerializer<UserAuthRequestPublicKeyHostboundOpenSshMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private static void serializeIncludesSignature(
            UserAuthRequestPublicKeyHostboundOpenSshMessage object, SerializerStream output) {
        LOGGER.debug(
                "Includes signature: {}",
                Converter.byteToBoolean(object.getIncludesSignature().getValue()));
        output.appendByte(object.getIncludesSignature().getValue());
    }

    private static void serializePublicKeyAlgorithmName(
            UserAuthRequestPublicKeyHostboundOpenSshMessage object, SerializerStream output) {
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
            UserAuthRequestPublicKeyHostboundOpenSshMessage object, SerializerStream output) {
        LOGGER.debug("Public key blob length: {}", object.getPublicKeyBlobLength().getValue());
        output.appendInt(object.getPublicKeyBlobLength().getValue());
        LOGGER.debug(
                "Public key blob: {}",
                () -> ArrayConverter.bytesToRawHexString(object.getPublicKeyBlob().getValue()));
        output.appendBytes(object.getPublicKeyBlob().getValue());
    }

    private static void serializeServerHostKeyBlob(
            UserAuthRequestPublicKeyHostboundOpenSshMessage object, SerializerStream output) {
        LOGGER.debug(
                "Server host key blob length: {}", object.getServerHostKeyBlobLength().getValue());
        output.appendInt(object.getServerHostKeyBlobLength().getValue());
        LOGGER.debug(
                "Server host key blob: {}",
                () -> ArrayConverter.bytesToRawHexString(object.getServerHostKeyBlob().getValue()));
        output.appendBytes(object.getServerHostKeyBlob().getValue());
    }

    private static void serializeSignature(
            UserAuthRequestPublicKeyHostboundOpenSshMessage object, SerializerStream output) {
        LOGGER.debug("Signature length: {}", object.getSignatureLength().getValue());
        output.appendInt(object.getSignatureLength().getValue());
        LOGGER.debug(
                "Signature: {}",
                () -> ArrayConverter.bytesToRawHexString(object.getSignature().getValue()));
        output.appendBytes(object.getSignature().getValue());
    }

    @Override
    protected void serializeMessageSpecificContents(
            UserAuthRequestPublicKeyHostboundOpenSshMessage object, SerializerStream output) {
        super.serializeMessageSpecificContents(object, output);
        serializeIncludesSignature(object, output);
        serializePublicKeyAlgorithmName(object, output);
        serializePublicKeyBlob(object, output);
        serializeServerHostKeyBlob(object, output);
        if (Converter.byteToBoolean(object.getIncludesSignature().getValue())) {
            serializeSignature(object, output);
        }
    }
}
