package de.rub.nds.sshattacker.protocol.parser;

import de.rub.nds.sshattacker.constants.BinaryPacketConstants;
import de.rub.nds.sshattacker.constants.PublicKeyAuthenticationAlgorithm;
import de.rub.nds.sshattacker.protocol.message.EcdhKeyExchangeReplyMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class EcdhKeyExchangeReplyMessageParser extends MessageParser<EcdhKeyExchangeReplyMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public EcdhKeyExchangeReplyMessageParser(int startposition, byte[] array) {
        super(startposition, array);
    }

    private void parseHostKeyLength(EcdhKeyExchangeReplyMessage msg) {
        msg.setHostKeyLength(parseIntField(BinaryPacketConstants.LENGTH_FIELD_LENGTH));
        LOGGER.debug("HostKeyLength: " + msg.getHostKeyLength().getValue());
    }

    private void parseHostKeyTypeLength(EcdhKeyExchangeReplyMessage msg) {
        msg.setHostKeyTypeLength(parseIntField(BinaryPacketConstants.LENGTH_FIELD_LENGTH));
        LOGGER.debug("HostKeyTypeLength: " + msg.getHostKeyTypeLength().getValue());
    }

    private void parseHostKeyType(EcdhKeyExchangeReplyMessage msg) {
        msg.setHostKeyType(parseByteString(msg.getHostKeyTypeLength().getValue()));
        LOGGER.debug("HostKeyType: " + msg.getHostKeyType().getValue());
    }

    private void parseHostKeyRsaExponentLength(EcdhKeyExchangeReplyMessage msg) {
        msg.setExponentLength(parseIntField(BinaryPacketConstants.LENGTH_FIELD_LENGTH));
        LOGGER.debug("ExponentLength: " + msg.getHostKeyRsaExponentLength().getValue());
    }

    private void parseHostKeyRsaExponent(EcdhKeyExchangeReplyMessage msg) {
        msg.setExponent(parseBigIntField(msg.getHostKeyRsaExponentLength().getValue()));
        LOGGER.debug("Exponent: " + msg.getHostKeyRsaExponent());
    }

    private void parseHostKeyRsaModulusLength(EcdhKeyExchangeReplyMessage msg) {
        msg.setModulusLength(parseIntField(BinaryPacketConstants.LENGTH_FIELD_LENGTH));
        LOGGER.debug("ModulusLength: " + msg.getHostKeyRsaModulusLength().getValue());
    }

    private void parseHostKeyRsaModulus(EcdhKeyExchangeReplyMessage msg) {
        msg.setModulus(parseBigIntField(msg.getHostKeyRsaModulusLength().getValue()));
        LOGGER.debug("Modulus: " + msg.getHostKeyRsaModulus());
    }

    private void parsePublicKeyLength(EcdhKeyExchangeReplyMessage msg) {
        msg.setPublicKeyLength(parseIntField(BinaryPacketConstants.LENGTH_FIELD_LENGTH));
        LOGGER.debug("PublicKeyLength: " + msg.getEphemeralPublicKeyLength().getValue());
    }

    private void parsePublicKey(EcdhKeyExchangeReplyMessage msg) {
        msg.setPublicKey(parseByteArrayField(msg.getEphemeralPublicKeyLength().getValue()));
        LOGGER.debug("PublicKey: " + msg.getEphemeralPublicKey());
    }

    private void parseSignatureLength(EcdhKeyExchangeReplyMessage msg) {
        msg.setSignatureLength(parseIntField(BinaryPacketConstants.LENGTH_FIELD_LENGTH));
        LOGGER.debug("SignatureLength: " + msg.getSignatureLength().getValue());
    }

    private void parseSignature(EcdhKeyExchangeReplyMessage msg) {
        msg.setSignature(parseByteArrayField(msg.getSignatureLength().getValue()));
        LOGGER.debug("Signature :" + msg.getSignature());
    }

    private void parseEccCurveIdentifierLength(EcdhKeyExchangeReplyMessage msg) {
        msg.setEccCurveIdentifierLength(parseIntField(BinaryPacketConstants.LENGTH_FIELD_LENGTH));
        LOGGER.debug("EccIdentifierLength: " + msg.getEccCurveIdentifierLength().getValue());
    }

    private void parseEccCurveIdentifier(EcdhKeyExchangeReplyMessage msg) {
        msg.setEccCurveIdentifier(parseByteString(msg.getEccCurveIdentifierLength().getValue()));
        LOGGER.debug("EccIdentifier: " + msg.getEccCurveIdentifier().getValue());
    }

    private void parseEccHostKeyLength(EcdhKeyExchangeReplyMessage msg) {
        msg.setHostKeyEccLength(parseIntField(BinaryPacketConstants.LENGTH_FIELD_LENGTH));
        LOGGER.debug("EccHostKeyLength: " + msg.getHostKeyEccLength().getValue());
    }

    private void parseEccHostKeyValue(EcdhKeyExchangeReplyMessage msg) {
        msg.setHostKeyEcc(parseByteArrayField(msg.getHostKeyEccLength().getValue()));
        LOGGER.debug("EccHostKey: " + msg.getHostKeyEcc());
    }

    @Override
    public void parseMessageSpecificPayload(EcdhKeyExchangeReplyMessage msg) {
        parseHostKeyLength(msg);
        parseHostKeyTypeLength(msg);
        parseHostKeyType(msg);
        if (msg.getHostKeyType().getValue().
                equals(PublicKeyAuthenticationAlgorithm.SSH_RSA.toString())) //TODO refine logic
        {
            parseRsaHostKey(msg);
        } else {
            parseEccHostKey(msg);
        }

        parsePublicKeyLength(msg);
        parsePublicKey(msg);
        parseSignatureLength(msg);
        parseSignature(msg);
    }

    private void parseEccHostKey(EcdhKeyExchangeReplyMessage msg) {
        parseEccCurveIdentifierLength(msg);
        parseEccCurveIdentifier(msg);
        parseEccHostKeyLength(msg);
        parseEccHostKeyValue(msg);
    }

    private void parseRsaHostKey(EcdhKeyExchangeReplyMessage msg) {
        parseHostKeyRsaExponentLength(msg);
        parseHostKeyRsaExponent(msg);
        parseHostKeyRsaModulusLength(msg);
        parseHostKeyRsaModulus(msg);
    }

    @Override
    public EcdhKeyExchangeReplyMessage createMessage() {
        return new EcdhKeyExchangeReplyMessage();
    }
}
