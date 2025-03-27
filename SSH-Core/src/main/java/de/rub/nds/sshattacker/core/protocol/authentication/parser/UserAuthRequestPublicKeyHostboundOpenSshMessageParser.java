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
import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthRequestPublicKeyHostboundOpenSshMessage;
import de.rub.nds.sshattacker.core.util.Converter;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class UserAuthRequestPublicKeyHostboundOpenSshMessageParser
        extends UserAuthRequestMessageParser<UserAuthRequestPublicKeyHostboundOpenSshMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public UserAuthRequestPublicKeyHostboundOpenSshMessageParser(byte[] array) {
        super(array);
    }

    public UserAuthRequestPublicKeyHostboundOpenSshMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    protected UserAuthRequestPublicKeyHostboundOpenSshMessage createMessage() {
        return new UserAuthRequestPublicKeyHostboundOpenSshMessage();
    }

    private void parseIncludesSignature() {
        message.setIncludesSignature(parseByteField(1));
        LOGGER.debug("Includes signature: {}", message.getIncludesSignature().getValue());
    }

    private void parsePublicKeyAlgorithmName() {
        message.setPublicKeyAlgorithmNameLength(
                parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        LOGGER.debug(
                "Public key algorithm name length: {}",
                message.getPublicKeyAlgorithmNameLength().getValue());
        message.setPublicKeyAlgorithmName(
                parseByteString(
                        message.getPublicKeyAlgorithmNameLength().getValue(),
                        StandardCharsets.US_ASCII));
        LOGGER.debug(
                "Public key algorithm name: {}",
                backslashEscapeString(message.getPublicKeyAlgorithmName().getValue()));
    }

    private void parsePublicKeyBlob() {
        message.setPublicKeyBlobLength(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        LOGGER.debug("Public key blob length: {}", message.getPublicKeyBlobLength().getValue());
        message.setPublicKeyBlob(parseByteArrayField(message.getPublicKeyBlobLength().getValue()));
        LOGGER.debug(
                "Public key blob: {}",
                ArrayConverter.bytesToRawHexString(message.getPublicKeyBlob().getValue()));
    }

    private void parseServerHostKeyBlob() {
        message.setServerHostKeyBlobLength(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        LOGGER.debug(
                "Server public key blob length: {}",
                message.getServerHostKeyBlobLength().getValue());
        message.setServerHostKeyBlob(
                parseByteArrayField(message.getServerHostKeyBlobLength().getValue()));
        LOGGER.debug(
                "Server public key blob: {}",
                ArrayConverter.bytesToRawHexString(message.getServerHostKeyBlob().getValue()));
    }

    private void parseSignature() {
        message.setSignatureLength(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        LOGGER.debug("Signature length: {}", message.getSignatureLength().getValue());
        message.setSignature(parseByteArrayField(message.getSignatureLength().getValue()));
        LOGGER.debug(
                "Signature: {}",
                ArrayConverter.bytesToRawHexString(message.getSignature().getValue()));
    }

    @Override
    protected void parseMessageSpecificContents() {
        super.parseMessageSpecificContents();
        parseIncludesSignature();
        parsePublicKeyAlgorithmName();
        parsePublicKeyBlob();
        parseServerHostKeyBlob();
        if (Converter.byteToBoolean(message.getIncludesSignature().getValue())) {
            parseSignature();
        }
    }
}
