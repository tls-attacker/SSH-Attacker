/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.authentication.parser;

import static de.rub.nds.modifiablevariable.util.StringUtil.backslashEscapeString;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthPubkeyMessage;
import de.rub.nds.sshattacker.core.util.Converter;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.nio.charset.StandardCharsets;

public class UserAuthPubkeyMessageParser
        extends UserAuthRequestMessageParser<UserAuthPubkeyMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public UserAuthPubkeyMessageParser(byte[] array) {
        super(array);
    }

    public UserAuthPubkeyMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    protected UserAuthPubkeyMessage createMessage() {
        return new UserAuthPubkeyMessage();
    }

    private void parsePubkey() {
        message.setPubkeyLength(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        LOGGER.debug("Pubkey length: " + message.getPubkeyLength().getValue());
        message.setPubkey(parseByteArrayField(message.getPubkeyLength().getValue()));
        LOGGER.debug(
                "Pubkey: {}", ArrayConverter.bytesToRawHexString(message.getPubkey().getValue()));
    }

    private void parsePubkeyAlgName() {
        message.setPubkeyAlgNameLength(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        LOGGER.debug(
                "Pubkey algorithm name length: " + message.getPubkeyAlgNameLength().getValue());
        message.setPubkeyAlgName(
                parseByteString(
                        message.getPubkeyAlgNameLength().getValue(), StandardCharsets.US_ASCII));
        LOGGER.debug(
                "Pubkey algorithm name: {}",
                backslashEscapeString(message.getPubkeyAlgName().getValue()));
    }

    private void parseUseSignature() {
        message.setUseSignature(parseByteField(1));
        LOGGER.debug("Use signature: " + message.getUseSignature().getValue());
    }

    private void parseSignature() {
        message.setSignatureLength(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        LOGGER.debug("Signature length: " + message.getSignatureLength().getValue());
        message.setSignature(parseByteArrayField(message.getSignatureLength().getValue()));
        LOGGER.debug(
                "Signature: {}",
                ArrayConverter.bytesToRawHexString(message.getSignature().getValue()));
    }

    @Override
    protected void parseMessageSpecificContents() {
        super.parseMessageSpecificContents();
        parseUseSignature();
        parsePubkeyAlgName();
        parsePubkey();
        if (Converter.byteToBoolean(message.getUseSignature().getValue())) {
            parseSignature();
        }
    }
}
