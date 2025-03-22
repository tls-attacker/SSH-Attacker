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
import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthPubkeyMessage;
import de.rub.nds.sshattacker.core.util.Converter;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

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
        int pubkeyLength = parseIntField();
        message.setPubkeyLength(pubkeyLength);
        LOGGER.debug("Pubkey length: {}", pubkeyLength);
        byte[] pubkey = parseByteArrayField(pubkeyLength);
        message.setPubkey(pubkey);
        LOGGER.debug("Pubkey: {}", () -> ArrayConverter.bytesToRawHexString(pubkey));
    }

    private void parsePubkeyAlgName() {
        int pubkeyAlgNameLength = parseIntField();
        message.setPubkeyAlgNameLength(pubkeyAlgNameLength);
        LOGGER.debug("Pubkey algorithm name length: {}", pubkeyAlgNameLength);
        String pubkeyAlgName = parseByteString(pubkeyAlgNameLength, StandardCharsets.US_ASCII);
        message.setPubkeyAlgName(pubkeyAlgName);
        LOGGER.debug("Pubkey algorithm name: {}", () -> backslashEscapeString(pubkeyAlgName));
    }

    private void parseUseSignature() {
        byte useSignature = parseByteField();
        message.setUseSignature(useSignature);
        LOGGER.debug("Use signature: {}", useSignature);
    }

    private void parseSignature() {
        int signatureLength = parseIntField();
        message.setSignatureLength(signatureLength);
        LOGGER.debug("Signature length: {}", signatureLength);
        byte[] signature = parseByteArrayField(signatureLength);
        message.setSignature(signature);
        LOGGER.debug("Signature: {}", () -> ArrayConverter.bytesToRawHexString(signature));
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
