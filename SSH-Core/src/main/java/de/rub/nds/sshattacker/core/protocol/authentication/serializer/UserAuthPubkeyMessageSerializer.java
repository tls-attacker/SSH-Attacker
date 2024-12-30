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
import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthPubkeyMessage;
import de.rub.nds.sshattacker.core.protocol.common.SerializerStream;
import de.rub.nds.sshattacker.core.util.Converter;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class UserAuthPubkeyMessageSerializer
        extends UserAuthRequestMessageSerializer<UserAuthPubkeyMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private static void serializeUseSignature(
            UserAuthPubkeyMessage object, SerializerStream output) {
        Byte useSignature = object.getUseSignature().getValue();
        LOGGER.debug("Use Signature: {}", () -> Converter.byteToBoolean(useSignature));
        output.appendByte(useSignature);
    }

    private static void serializePubkeyAlgName(
            UserAuthPubkeyMessage object, SerializerStream output) {
        Integer pubkeyAlgNameLength = object.getPubkeyAlgNameLength().getValue();
        LOGGER.debug("Pubkey algorithm name length: {}", pubkeyAlgNameLength);
        output.appendInt(pubkeyAlgNameLength);
        String pubkeyAlgName = object.getPubkeyAlgName().getValue();
        LOGGER.debug("Pubkey algorithm name: {}", () -> backslashEscapeString(pubkeyAlgName));
        output.appendString(pubkeyAlgName, StandardCharsets.US_ASCII);
    }

    private static void serializePubkey(UserAuthPubkeyMessage object, SerializerStream output) {
        Integer pubkeyLength = object.getPubkeyLength().getValue();
        LOGGER.debug("Pubkey length: {}", pubkeyLength);
        output.appendInt(pubkeyLength);
        byte[] pubkey = object.getPubkey().getValue();
        LOGGER.debug("Pubkey: {}", () -> ArrayConverter.bytesToRawHexString(pubkey));
        output.appendBytes(pubkey);
    }

    private static void serializeSignature(UserAuthPubkeyMessage object, SerializerStream output) {
        Integer signatureLength = object.getSignatureLength().getValue();
        LOGGER.debug("Signature length: {}", signatureLength);
        output.appendInt(signatureLength);
        byte[] signature = object.getSignature().getValue();
        LOGGER.debug("Signature: {}", () -> ArrayConverter.bytesToRawHexString(signature));
        output.appendBytes(signature);
    }

    @Override
    protected void serializeMessageSpecificContents(
            UserAuthPubkeyMessage object, SerializerStream output) {
        super.serializeMessageSpecificContents(object, output);
        serializeUseSignature(object, output);
        serializePubkeyAlgName(object, output);
        serializePubkey(object, output);
        if (Converter.byteToBoolean(object.getUseSignature().getValue())) {
            serializeSignature(object, output);
        }
    }
}
