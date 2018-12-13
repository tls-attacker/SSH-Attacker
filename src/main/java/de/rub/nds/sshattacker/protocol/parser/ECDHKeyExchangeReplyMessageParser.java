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
        LOGGER.debug("HostKeyTypeLength: " + msg.getHostKeyTypeLength().getValue());
    }

    private void parseHostKeyType(ECDHKeyExchangeReplyMessage msg) {
        msg.setHostKeyType(parseByteString(msg.getHostKeyTypeLength().getValue()));
        LOGGER.debug("HostKeyType: " + msg.getHostKeyType().getValue());
    }

    private void parseHostKeyRsaExponentLength(ECDHKeyExchangeReplyMessage msg) {
        msg.setExponentLength(parseIntField(BinaryPacketConstants.LENGTH_FIELD_LENGTH));
        LOGGER.debug("ExponentLength: " + msg.getHostKeyRsaExponentLength().getValue());
    }

    private void parseHostKeyRsaExponent(ECDHKeyExchangeReplyMessage msg) {
        msg.setExponent(parseBigIntField(msg.getHostKeyRsaExponentLength().getValue()));
        LOGGER.debug("Exponent: " + msg.getHostKeyRsaExponent());
    }

    private void parseHostKeyRsaModulusLength(ECDHKeyExchangeReplyMessage msg) {
        msg.setModulusLength(parseIntField(BinaryPacketConstants.LENGTH_FIELD_LENGTH));
        LOGGER.debug("ModulusLength: " + msg.getHostKeyRsaModulusLength().getValue());
    }

    private void parseHostKeyRsaModulus(ECDHKeyExchangeReplyMessage msg) {
        msg.setModulus(parseBigIntField(msg.getHostKeyRsaModulusLength().getValue()));
        LOGGER.debug("Modulus: " + msg.getHostKeyRsaModulus());
    }

    private void parsePublicKeyLength(ECDHKeyExchangeReplyMessage msg) {
        msg.setPublicKeyLength(parseIntField(BinaryPacketConstants.LENGTH_FIELD_LENGTH));
        LOGGER.debug("PublicKeyLength: " + msg.getEphemeralPublicKeyLength().getValue());
    }

    private void parsePublicKey(ECDHKeyExchangeReplyMessage msg) {
        msg.setPublicKey(parseByteArrayField(msg.getEphemeralPublicKeyLength().getValue()));
        LOGGER.debug("PublicKey: " + msg.getEphemeralPublicKey());
    }

    private void parseSignatureLength(ECDHKeyExchangeReplyMessage msg) {
        msg.setSignatureLength(parseIntField(BinaryPacketConstants.LENGTH_FIELD_LENGTH));
        LOGGER.debug("SignatureLength: " + msg.getSignatureLength().getValue());
    }

    private void parseSignature(ECDHKeyExchangeReplyMessage msg) {
        msg.setSignature(parseByteArrayField(msg.getSignatureLength().getValue()));
        LOGGER.debug("Signature :" + msg.getSignature());
    }

    private void parseEccCurveIdentifierLength(ECDHKeyExchangeReplyMessage msg){
        msg.setEccCurveIdentifierLength(parseIntField(BinaryPacketConstants.LENGTH_FIELD_LENGTH));
        LOGGER.debug("EccIdentifierLength: " + msg.getEccCurveIdentifierLength().getValue());
    }

    private void parseEccCurveIdentifier(ECDHKeyExchangeReplyMessage msg){
        msg.setEccCurveIdentifier(parseByteString(msg.getEccCurveIdentifierLength().getValue()));
        LOGGER.debug("EccIdentifier: " + msg.getEccCurveIdentifier().getValue());
    }
    
    private void parseEccHostKeyLength(ECDHKeyExchangeReplyMessage msg){
        msg.setHostKeyEccLength(parseIntField(BinaryPacketConstants.LENGTH_FIELD_LENGTH));
        LOGGER.debug("EccHostKeyLength: " + msg.getHostKeyEccLength().getValue());
    }
    
    private void parseEccHostKeyValue(ECDHKeyExchangeReplyMessage msg){
        msg.setHostKeyEcc(parseByteArrayField(msg.getHostKeyEccLength().getValue()));
        LOGGER.debug("EccHostKey: " + msg.getHostKeyEcc());
    }
    
    @Override
    public void parseMessageSpecificPayload(ECDHKeyExchangeReplyMessage msg) {
        parseHostKeyLength(msg);
        parseHostKeyTypeLength(msg);
        parseHostKeyType(msg);
        //parseRsaHostKey(msg);
        parseEccHostKey(msg);
        parsePublicKeyLength(msg);
        parsePublicKey(msg);
        parseSignatureLength(msg);
        parseSignature(msg);
    }

    private void parseEccHostKey(ECDHKeyExchangeReplyMessage msg){
        parseEccCurveIdentifierLength(msg);
        parseEccCurveIdentifier(msg);
        parseEccHostKeyLength(msg);
        parseEccHostKeyValue(msg);
    }
    
    private void parseRsaHostKey(ECDHKeyExchangeReplyMessage msg){
        parseHostKeyRsaExponentLength(msg);
        parseHostKeyRsaExponent(msg);
        parseHostKeyRsaModulusLength(msg);
        parseHostKeyRsaModulus(msg);
    }
    
    @Override
    public ECDHKeyExchangeReplyMessage createMessage() {
        return new ECDHKeyExchangeReplyMessage();
    }
}
