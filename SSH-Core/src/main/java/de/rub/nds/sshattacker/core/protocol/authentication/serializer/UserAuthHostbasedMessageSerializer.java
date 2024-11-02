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
import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthHostbasedMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class UserAuthHostbasedMessageSerializer
        extends UserAuthRequestMessageSerializer<UserAuthHostbasedMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public UserAuthHostbasedMessageSerializer(UserAuthHostbasedMessage message) {
        super(message);
    }

    private void serializePubKeyAlgorithm() {
        Integer pubKeyAlgorithmLength = message.getPubKeyAlgorithmLength().getValue();
        LOGGER.debug("Public key algorithm length: {}", pubKeyAlgorithmLength);
        appendInt(pubKeyAlgorithmLength, DataFormatConstants.STRING_SIZE_LENGTH);
        String pubKeyAlgorithm = message.getPubKeyAlgorithm().getValue();
        LOGGER.debug("Public key algorithm: {}", () -> backslashEscapeString(pubKeyAlgorithm));
        appendString(pubKeyAlgorithm);
    }

    private void serializeHostKeyBytes() {
        Integer hostKeyBytesLength = message.getHostKeyBytesLength().getValue();
        LOGGER.debug("Host key length: {}", hostKeyBytesLength);
        appendInt(hostKeyBytesLength, DataFormatConstants.STRING_SIZE_LENGTH);
        byte[] hostKeyBytes = message.getHostKeyBytes().getValue();
        LOGGER.debug("Host key: {}", () -> ArrayConverter.bytesToRawHexString(hostKeyBytes));
        appendBytes(hostKeyBytes);
    }

    private void serializeHostName() {
        Integer hostNameLength = message.getHostNameLength().getValue();
        LOGGER.debug("Host name length: {}", hostNameLength);
        appendInt(hostNameLength, DataFormatConstants.STRING_SIZE_LENGTH);
        String hostName = message.getHostName().getValue();
        LOGGER.debug("Host name: {}", () -> backslashEscapeString(hostName));
        appendString(hostName);
    }

    private void serializeClientUserName() {
        Integer clientUserNameLength = message.getClientUserNameLength().getValue();
        LOGGER.debug("Client user name length: {}", clientUserNameLength);
        appendInt(clientUserNameLength, DataFormatConstants.STRING_SIZE_LENGTH);
        String clientUserName = message.getClientUserName().getValue();
        LOGGER.debug("Client user name: {}", () -> backslashEscapeString(clientUserName));
        appendString(clientUserName);
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
        serializePubKeyAlgorithm();
        serializeHostKeyBytes();
        serializeHostName();
        serializeClientUserName();
        serializeSignature();
    }
}
