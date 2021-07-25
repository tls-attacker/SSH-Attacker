/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.parser;

import de.rub.nds.sshattacker.core.constants.BinaryPacketConstants;
import de.rub.nds.sshattacker.core.constants.PublicKeyAuthenticationAlgorithm;
import de.rub.nds.sshattacker.core.protocol.common.MessageParser;
import de.rub.nds.sshattacker.core.protocol.transport.message.DhKeyExchangeReplyMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class DhKeyExchangeReplyMessageParser extends MessageParser<DhKeyExchangeReplyMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public DhKeyExchangeReplyMessageParser(int startPosition, byte[] array) {
        super(startPosition, array);
    }

    private void parseHostKeyLength(DhKeyExchangeReplyMessage msg) {
        msg.setHostKeyLength(parseIntField(BinaryPacketConstants.LENGTH_FIELD_LENGTH));
        LOGGER.debug("Host key length: " + msg.getHostKeyLength().getValue());
    }

    private void parseHostKeyTypeLength(DhKeyExchangeReplyMessage msg) {
        msg.setHostKeyTypeLength(parseIntField(BinaryPacketConstants.LENGTH_FIELD_LENGTH));
        LOGGER.debug("Host key type length: " + msg.getHostKeyTypeLength().getValue());
    }

    private void parseHostKeyType(DhKeyExchangeReplyMessage msg) {
        msg.setHostKeyType(parseByteString(msg.getHostKeyTypeLength().getValue()));
        LOGGER.debug("Host key type: " + msg.getHostKeyType().getValue());
    }

    private void parseHostKeyRsaExponentLength(DhKeyExchangeReplyMessage msg) {
        msg.setHostKeyRsaExponentLength(parseIntField(BinaryPacketConstants.LENGTH_FIELD_LENGTH));
        LOGGER.debug("Exponent length: " + msg.getHostKeyRsaExponentLength().getValue());
    }

    private void parseHostKeyRsaExponent(DhKeyExchangeReplyMessage msg) {
        msg.setHostKeyRsaExponent(parseBigIntField(msg.getHostKeyRsaExponentLength().getValue()));
        LOGGER.debug("Exponent: " + msg.getHostKeyRsaExponent());
    }

    private void parseHostKeyRsaModulusLength(DhKeyExchangeReplyMessage msg) {
        msg.setHostKeyRsaModulusLength(parseIntField(BinaryPacketConstants.LENGTH_FIELD_LENGTH));
        LOGGER.debug("Modulus length: " + msg.getHostKeyRsaModulusLength().getValue());
    }

    private void parseHostKeyRsaModulus(DhKeyExchangeReplyMessage msg) {
        msg.setHostKeyRsaModulus(parseBigIntField(msg.getHostKeyRsaModulusLength().getValue()));
        LOGGER.debug("Modulus: " + msg.getHostKeyRsaModulus());
    }

    private void parsePublicKeyLength(DhKeyExchangeReplyMessage msg) {
        msg.setEphemeralPublicKeyLength(parseIntField(BinaryPacketConstants.LENGTH_FIELD_LENGTH));
        LOGGER.debug("Ephemeral public key length: " + msg.getEphemeralPublicKeyLength().getValue());
    }

    private void parsePublicKey(DhKeyExchangeReplyMessage msg) {
        msg.setEphemeralPublicKey(parseBigIntField(msg.getEphemeralPublicKeyLength().getValue()));
        LOGGER.debug("Ephemeral public key: " + msg.getEphemeralPublicKey());
    }

    private void parseSignatureLength(DhKeyExchangeReplyMessage msg) {
        msg.setSignatureLength(parseIntField(BinaryPacketConstants.LENGTH_FIELD_LENGTH));
        LOGGER.debug("Signature length: " + msg.getSignatureLength().getValue());
    }

    private void parseSignature(DhKeyExchangeReplyMessage msg) {
        msg.setSignature(parseByteArrayField(msg.getSignatureLength().getValue()));
        LOGGER.debug("Signature: " + msg.getSignature());
    }

    @Override
    protected void parseMessageSpecificPayload(DhKeyExchangeReplyMessage msg) {
        parseHostKeyLength(msg);
        parseHostKeyTypeLength(msg);
        parseHostKeyType(msg);
        if (msg.getHostKeyType().getValue().equals(PublicKeyAuthenticationAlgorithm.SSH_RSA.toString())) {
            parseRsaHostKey(msg);
        } else {
            LOGGER.warn("Unable to parse host key of unsupported host key type " + msg.getHostKeyType().getValue());
            // Skip the remaining bytes of the host key
            parseByteArrayField(msg.getHostKeyLength().getValue() - BinaryPacketConstants.LENGTH_FIELD_LENGTH
                    - msg.getHostKeyTypeLength().getValue());
        }
        parsePublicKeyLength(msg);
        parsePublicKey(msg);
        parseSignatureLength(msg);
        parseSignature(msg);
    }

    private void parseRsaHostKey(DhKeyExchangeReplyMessage msg) {
        parseHostKeyRsaExponentLength(msg);
        parseHostKeyRsaExponent(msg);
        parseHostKeyRsaModulusLength(msg);
        parseHostKeyRsaModulus(msg);
    }

    @Override
    public DhKeyExchangeReplyMessage createMessage() {
        return new DhKeyExchangeReplyMessage();
    }
}
