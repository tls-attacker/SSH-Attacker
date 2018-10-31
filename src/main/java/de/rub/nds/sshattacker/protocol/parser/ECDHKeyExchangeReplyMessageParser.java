package de.rub.nds.sshattacker.protocol.parser;

import de.rub.nds.sshattacker.constants.BinaryPacketConstants;
import de.rub.nds.sshattacker.protocol.message.ECDHKeyExchangeReplyMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ECDHKeyExchangeReplyMessageParser extends BinaryPacketParser<ECDHKeyExchangeReplyMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ECDHKeyExchangeReplyMessageParser(int startposition, byte[] array) {
        super(startposition, array);
    }

    private void parseHostKeyLength(ECDHKeyExchangeReplyMessage msg) {
        msg.setHostKeyLength(parseIntField(BinaryPacketConstants.LENGTH_FIELD_LENGTH));
        LOGGER.debug("HostKeyLength: " + msg.getHostKeyLength().getValue());
    }

    private void parseHostKeyTypeLength(ECDHKeyExchangeReplyMessage msg) {
        msg.setHostKeyTypeLength(parseIntField(BinaryPacketConstants.LENGTH_FIELD_LENGTH));
        LOGGER.debug("HostKeyTypeLength: " + msg.getHostKeyLength().getValue());
    }

    private void parseHostKeyType(ECDHKeyExchangeReplyMessage msg) {
        msg.setHostKeyType(parseByteString(msg.getHostKeyTypeLength().getValue()));
        LOGGER.debug("HostKeyType: " + msg.getHostKeyType());
    }

    private void parseExponentLength(ECDHKeyExchangeReplyMessage msg) {
        msg.setExponentLength(parseIntField(BinaryPacketConstants.LENGTH_FIELD_LENGTH));
        LOGGER.debug("ExponentLength: " + msg.getExponentLength().getValue());
    }

    private void parseExponent(ECDHKeyExchangeReplyMessage msg) {
        msg.setExponent(parseByteArrayField(msg.getExponentLength().getValue()));
        LOGGER.debug("Exponent: " + msg.getExponent());
    }

    private void parseModulusLength(ECDHKeyExchangeReplyMessage msg) {
        msg.setModulusLength(parseIntField(BinaryPacketConstants.LENGTH_FIELD_LENGTH));
        LOGGER.debug("ModulusLength: " + msg.getModulusLength().getValue());
    }

    private void parseModulus(ECDHKeyExchangeReplyMessage msg) {
        msg.setModulus(parseByteArrayField(msg.getModulusLength().getValue()));
        LOGGER.debug("Modulus: " + msg.getModulus());
    }

    private void parsePublicKeyLength(ECDHKeyExchangeReplyMessage msg) {
        msg.setPublicKeyLength(parseIntField(BinaryPacketConstants.LENGTH_FIELD_LENGTH));
        LOGGER.debug("PublicKeyLength: " + msg.getPublicKeyLength().getValue());
    }

    private void parsePublicKey(ECDHKeyExchangeReplyMessage msg) {
        msg.setPublicKey(parseByteArrayField(msg.getPublicKeyLength().getValue()));
        LOGGER.debug("PublicKey: " + msg.getPublicKey());
    }

    private void parseSignatureLength(ECDHKeyExchangeReplyMessage msg) {
        msg.setSignatureLength(parseIntField(BinaryPacketConstants.LENGTH_FIELD_LENGTH));
        LOGGER.debug("SignatureLength: " + msg.getSignatureLength().getValue());
    }

    private void parseSignature(ECDHKeyExchangeReplyMessage msg) {
        msg.setSignature(parseByteArrayField(msg.getSignatureLength().getValue()));
        LOGGER.debug("Signature :" + msg.getSignature());
    }

    @Override
    public void parseMessageSpecificPayload(ECDHKeyExchangeReplyMessage msg) {
        parseHostKeyLength(msg);
        parseHostKeyTypeLength(msg);
        parseHostKeyType(msg);
        parseExponentLength(msg);
        parseExponent(msg);
        parseModulusLength(msg);
        parseModulus(msg);
        parsePublicKeyLength(msg);
        parsePublicKey(msg);
        parseSignatureLength(msg);
        parseSignature(msg);
    }

    @Override
    public ECDHKeyExchangeReplyMessage createMessage() {
        return new ECDHKeyExchangeReplyMessage();
    }
}
