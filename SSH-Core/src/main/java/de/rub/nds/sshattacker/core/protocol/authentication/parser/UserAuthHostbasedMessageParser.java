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
import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthHostbasedMessage;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class UserAuthHostbasedMessageParser
        extends UserAuthRequestMessageParser<UserAuthHostbasedMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public UserAuthHostbasedMessageParser(byte[] array) {
        super(array);
    }

    public UserAuthHostbasedMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    protected UserAuthHostbasedMessage createMessage() {
        return new UserAuthHostbasedMessage();
    }

    private void parsePubKeyAlgorithm() {
        int pubKeyAlgorithmLength = parseIntField();
        message.setPubKeyAlgorithmLength(pubKeyAlgorithmLength);
        LOGGER.debug("Public key algorithm length: {}", pubKeyAlgorithmLength);
        String pubKeyAlgorithm = parseByteString(pubKeyAlgorithmLength);
        message.setPubKeyAlgorithm(pubKeyAlgorithm);
        LOGGER.debug("Public key algorithm: {}", () -> backslashEscapeString(pubKeyAlgorithm));
    }

    private void parseHostKeyBytes() {
        int hostKeyBytesLength = parseIntField();
        message.setHostKeyBytesLength(hostKeyBytesLength);
        LOGGER.debug("Host key bytes length: {}", hostKeyBytesLength);
        byte[] hostKeyBytes = parseByteArrayField(hostKeyBytesLength);
        message.setHostKeyBytes(hostKeyBytes);
        LOGGER.debug("Host key bytes: {}", () -> ArrayConverter.bytesToRawHexString(hostKeyBytes));
    }

    private void parseHostName() {
        int hostNameLength = parseIntField();
        message.setHostNameLength(hostNameLength);
        LOGGER.debug("Host name length: {}", hostNameLength);
        String hostName = parseByteString(hostNameLength);
        message.setHostName(hostName);
        LOGGER.debug("Host name: {}", () -> backslashEscapeString(hostName));
    }

    private void parseClientUserName() {
        int clientUserNameLength = parseIntField();
        message.setClientUserNameLength(clientUserNameLength);
        LOGGER.debug("Client user name length: {}", clientUserNameLength);
        String clientUserName = parseByteString(clientUserNameLength, StandardCharsets.UTF_8);
        message.setClientUserName(clientUserName);
        LOGGER.debug("Client user name: {}", () -> backslashEscapeString(clientUserName));
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
        parsePubKeyAlgorithm();
        parseHostKeyBytes();
        parseHostName();
        parseClientUserName();
        parseSignature();
    }
}
