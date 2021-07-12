/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.parser;

import de.rub.nds.sshattacker.core.constants.BinaryPacketConstants;
import de.rub.nds.sshattacker.core.constants.PublicKeyAuthenticationAlgorithm;
import de.rub.nds.sshattacker.core.protocol.message.DhGexKeyExchangeReplyMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class DhGexKeyExchangeReplyMessageParser extends MessageParser<DhGexKeyExchangeReplyMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public DhGexKeyExchangeReplyMessageParser(int startPosition, byte[] array) {
        super(startPosition, array);
    }

    private void parseHostKeyLength(DhGexKeyExchangeReplyMessage msg) {
        msg.setHostKeyLength(parseIntField(BinaryPacketConstants.LENGTH_FIELD_LENGTH));
        LOGGER.debug("Host key length: " + msg.getHostKeyLength().getValue());
    }

    private void parseHostKeyTypeLength(DhGexKeyExchangeReplyMessage msg) {
        msg.setHostKeyTypeLength(parseIntField(BinaryPacketConstants.LENGTH_FIELD_LENGTH));
        LOGGER.debug("Host key type length: " + msg.getHostKeyTypeLength().getValue());
    }

    private void parseHostKeyType(DhGexKeyExchangeReplyMessage msg) {
        msg.setHostKeyType(parseByteString(msg.getHostKeyTypeLength().getValue()));
        LOGGER.debug("Host key type: " + msg.getHostKeyType().getValue());
    }

    private void parseHostKeyRsaExponentLength(DhGexKeyExchangeReplyMessage msg) {
        msg.setHostKeyRsaExponentLength(parseIntField(BinaryPacketConstants.LENGTH_FIELD_LENGTH));
        LOGGER.debug("Exponent length: " + msg.getHostKeyRsaExponentLength().getValue());
    }

    private void parseHostKeyRsaExponent(DhGexKeyExchangeReplyMessage msg) {
        msg.setHostKeyRsaExponent(parseBigIntField(msg.getHostKeyRsaExponentLength().getValue()));
        LOGGER.debug("Exponent: " + msg.getHostKeyRsaExponent());
    }

    private void parseHostKeyRsaModulusLength(DhGexKeyExchangeReplyMessage msg) {
        msg.setHostKeyRsaModulusLength(parseIntField(BinaryPacketConstants.LENGTH_FIELD_LENGTH));
        LOGGER.debug("Modulus length: " + msg.getHostKeyRsaModulusLength().getValue());
    }

    private void parseHostKeyRsaModulus(DhGexKeyExchangeReplyMessage msg) {
        msg.setHostKeyRsaModulus(parseBigIntField(msg.getHostKeyRsaModulusLength().getValue()));
        LOGGER.debug("Modulus: " + msg.getHostKeyRsaModulus());
    }

    private void parsePublicKeyLength(DhGexKeyExchangeReplyMessage msg) {
        msg.setEphemeralPublicKeyLength(parseIntField(BinaryPacketConstants.LENGTH_FIELD_LENGTH));
        LOGGER.debug("Ephemeral public key length: " + msg.getEphemeralPublicKeyLength().getValue());
    }

    private void parsePublicKey(DhGexKeyExchangeReplyMessage msg) {
        msg.setEphemeralPublicKey(parseBigIntField(msg.getEphemeralPublicKeyLength().getValue()));
        LOGGER.debug("Ephemeral public key: " + msg.getEphemeralPublicKey());
    }

    private void parseSignatureLength(DhGexKeyExchangeReplyMessage msg) {
        msg.setSignatureLength(parseIntField(BinaryPacketConstants.LENGTH_FIELD_LENGTH));
        LOGGER.debug("Signature length: " + msg.getSignatureLength().getValue());
    }

    private void parseSignature(DhGexKeyExchangeReplyMessage msg) {
        msg.setSignature(parseByteArrayField(msg.getSignatureLength().getValue()));
        LOGGER.debug("Signature: " + msg.getSignature());
    }

    @Override
    protected void parseMessageSpecificPayload(DhGexKeyExchangeReplyMessage msg) {
        parseHostKeyLength(msg);
        parseHostKeyTypeLength(msg);
        parseHostKeyType(msg);
        if (msg.getHostKeyType().getValue().equals(PublicKeyAuthenticationAlgorithm.SSH_RSA.toString())) {
            parseRsaHostKey(msg);
        } else {
            LOGGER.warn("Unable to parse host key of unsupported host key type " + msg.getHostKeyType().getValue());
        }
        parsePublicKeyLength(msg);
        parsePublicKey(msg);
        parseSignatureLength(msg);
        parseSignature(msg);
    }

    private void parseRsaHostKey(DhGexKeyExchangeReplyMessage msg) {
        parseHostKeyRsaExponentLength(msg);
        parseHostKeyRsaExponent(msg);
        parseHostKeyRsaModulusLength(msg);
        parseHostKeyRsaModulus(msg);
    }

    @Override
    public DhGexKeyExchangeReplyMessage createMessage() {
        return new DhGexKeyExchangeReplyMessage();
    }
}
