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
import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthPubkeyMessage;
import de.rub.nds.sshattacker.core.util.Converter;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.nio.charset.StandardCharsets;

public class UserAuthPubkeyMessageSerializer
        extends UserAuthRequestMessageSerializer<UserAuthPubkeyMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public UserAuthPubkeyMessageSerializer(UserAuthPubkeyMessage message) {
        super(message);
    }

    private void serializeUseSignature() {
        LOGGER.debug(
                "Use Signature: " + Converter.byteToBoolean(message.getUseSignature().getValue()));
        appendByte(message.getUseSignature().getValue());
    }

    private void serializePubkeyAlgName() {
        LOGGER.debug(
                "Pubkey algorithm name length: " + message.getPubkeyAlgNameLength().getValue());
        appendInt(
                message.getPubkeyAlgNameLength().getValue(),
                DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug(
                "Pubkey algorithm name: {}",
                backslashEscapeString(message.getPubkeyAlgName().getValue()));
        appendString(message.getPubkeyAlgName().getValue(), StandardCharsets.US_ASCII);
    }

    private void serializePubkey() {
        LOGGER.debug("Pubkey length: " + message.getPubkeyLength().getValue());
        appendInt(message.getPubkeyLength().getValue(), DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug(
                "Pubkey: {}", ArrayConverter.bytesToRawHexString((message.getPubkey().getValue())));
        appendBytes(message.getPubkey().getValue());
    }

    private void serializeSignature() {
        LOGGER.debug("Signature length: " + message.getSignatureLength().getValue());
        appendInt(message.getSignatureLength().getValue(), DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug(
                "Signature: {}",
                ArrayConverter.bytesToRawHexString(message.getSignature().getValue()));
        appendBytes(message.getSignature().getValue());
    }

    @Override
    public void serializeMessageSpecificContents() {
        super.serializeMessageSpecificContents();
        serializeUseSignature();
        serializePubkeyAlgName();
        serializePubkey();
        if (Converter.byteToBoolean(message.getUseSignature().getValue())) {
            serializeSignature();
        }
    }
}
