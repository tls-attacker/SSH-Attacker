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
import de.rub.nds.sshattacker.core.constants.BinaryPacketConstants;
import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthHostbasedMessage;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class UserAuthHostbasedMessageParser
        extends UserAuthRequestMessageParser<UserAuthHostbasedMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public UserAuthHostbasedMessageParser(InputStream stream) {
        super(stream);
    }

    @Override
    public void parse(UserAuthHostbasedMessage message) {
        LOGGER.debug("Parsing UserAuthBannerMessage");
        parseProtocolMessageContents(message);
        message.setCompleteResultingMessage(getAlreadyParsed());
    }

    private void parsePubKeyAlgorithm(UserAuthHostbasedMessage message) {
        message.setPubKeyAlgorithmLength(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        LOGGER.debug(
                "Public key algorithm length: {}", message.getPubKeyAlgorithmLength().getValue());
        message.setPubKeyAlgorithm(parseByteString(message.getPubKeyAlgorithmLength().getValue()));
        LOGGER.debug(
                "Public key algorithm: {}",
                backslashEscapeString(message.getPubKeyAlgorithm().getValue()));
    }

    private void parseHostKeyBytes(UserAuthHostbasedMessage message) {
        message.setHostKeyBytesLength(parseIntField(BinaryPacketConstants.LENGTH_FIELD_LENGTH));
        LOGGER.debug("Host key bytes length: {}", message.getHostKeyBytesLength().getValue());
        message.setHostKeyBytes(parseByteArrayField(message.getHostKeyBytesLength().getValue()));
        LOGGER.debug(
                "Host key bytes: {}",
                ArrayConverter.bytesToRawHexString(message.getHostKeyBytes().getValue()));
    }

    private void parseHostName(UserAuthHostbasedMessage message) {
        message.setHostNameLength(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        LOGGER.debug("Host name length: {}", message.getHostNameLength().getValue());
        message.setHostName(parseByteString(message.getHostNameLength().getValue()));
        LOGGER.debug("Host name: {}", backslashEscapeString(message.getHostName().getValue()));
    }

    private void parseClientUserName(UserAuthHostbasedMessage message) {
        message.setClientUserNameLength(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        LOGGER.debug("Client user name length: {}", message.getClientUserNameLength().getValue());
        message.setClientUserName(
                parseByteString(
                        message.getClientUserNameLength().getValue(), StandardCharsets.UTF_8));
        LOGGER.debug(
                "Client user name: {}",
                backslashEscapeString(message.getClientUserName().getValue()));
    }

    private void parseSignature(UserAuthHostbasedMessage message) {
        message.setSignatureLength(parseIntField(BinaryPacketConstants.LENGTH_FIELD_LENGTH));
        LOGGER.debug("Signature length: {}", message.getSignatureLength().getValue());
        message.setSignature(parseByteArrayField(message.getSignatureLength().getValue()));
        LOGGER.debug("Signature: {}", message.getSignature());
    }

    @Override
    protected void parseMessageSpecificContents(UserAuthHostbasedMessage message) {
        super.parseMessageSpecificContents(message);
        parsePubKeyAlgorithm(message);
        parseHostKeyBytes(message);
        parseHostName(message);
        parseClientUserName(message);
        parseSignature(message);
    }
}
