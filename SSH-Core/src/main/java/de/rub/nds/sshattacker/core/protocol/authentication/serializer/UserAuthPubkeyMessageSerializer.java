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
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class UserAuthPubkeyMessageSerializer
        extends UserAuthRequestMessageSerializer<UserAuthPubkeyMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public UserAuthPubkeyMessageSerializer(UserAuthPubkeyMessage message) {
        super(message);
    }

    private void serializeUseSignature() {
        Byte useSignature = message.getUseSignature().getValue();
        LOGGER.debug("Use Signature: {}", () -> Converter.byteToBoolean(useSignature));
        appendByte(useSignature);
    }

    private void serializePubkeyAlgName() {
        Integer pubkeyAlgNameLength = message.getPubkeyAlgNameLength().getValue();
        LOGGER.debug("Pubkey algorithm name length: {}", pubkeyAlgNameLength);
        appendInt(pubkeyAlgNameLength, DataFormatConstants.STRING_SIZE_LENGTH);
        String pubkeyAlgName = message.getPubkeyAlgName().getValue();
        LOGGER.debug("Pubkey algorithm name: {}", () -> backslashEscapeString(pubkeyAlgName));
        appendString(pubkeyAlgName, StandardCharsets.US_ASCII);
    }

    private void serializePubkey() {
        Integer pubkeyLength = message.getPubkeyLength().getValue();
        LOGGER.debug("Pubkey length: {}", pubkeyLength);
        appendInt(pubkeyLength, DataFormatConstants.STRING_SIZE_LENGTH);
        byte[] pubkey = message.getPubkey().getValue();
        LOGGER.debug("Pubkey: {}", () -> ArrayConverter.bytesToRawHexString(pubkey));
        appendBytes(pubkey);
    }

    private void serializeSignature() {
        Integer signatureLength = message.getSignatureLength().getValue();
        LOGGER.debug("Signature length: {}", signatureLength);
        appendInt(signatureLength, DataFormatConstants.STRING_SIZE_LENGTH);
        byte[] signature = message.getSignature().getValue();
        LOGGER.debug("Signature: {}", () -> ArrayConverter.bytesToRawHexString(signature));
        appendBytes(signature);
    }

    @Override
    protected void serializeMessageSpecificContents() {
        super.serializeMessageSpecificContents();
        serializeUseSignature();
        serializePubkeyAlgName();
        serializePubkey();
        if (Converter.byteToBoolean(message.getUseSignature().getValue())) {
            serializeSignature();
        }
    }
}
