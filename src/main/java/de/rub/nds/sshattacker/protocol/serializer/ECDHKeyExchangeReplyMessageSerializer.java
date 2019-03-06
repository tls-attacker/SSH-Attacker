package de.rub.nds.sshattacker.protocol.serializer;

import de.rub.nds.sshattacker.constants.BinaryPacketConstants;
import de.rub.nds.sshattacker.protocol.message.ECDHKeyExchangeReplyMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ECDHKeyExchangeReplyMessageSerializer extends MessageSerializer<ECDHKeyExchangeReplyMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ECDHKeyExchangeReplyMessageSerializer(ECDHKeyExchangeReplyMessage msg) {
        super(msg);
        this.msg = msg;
    }

    private final ECDHKeyExchangeReplyMessage msg;

    private void serializeHostKeyLength(ECDHKeyExchangeReplyMessage msg) {
        appendInt(msg.getHostKeyLength().getValue(), BinaryPacketConstants.LENGTH_FIELD_LENGTH);
        LOGGER.debug("HostKeyLength: " + msg.getHostKeyLength().getValue());
    }

    private void serializeHostKeyTypeLength(ECDHKeyExchangeReplyMessage msg) {
        appendInt(msg.getHostKeyTypeLength().getValue(), BinaryPacketConstants.LENGTH_FIELD_LENGTH);
        LOGGER.debug("HostKeyTypeLength: " + msg.getHostKeyTypeLength().getValue());
    }

    private void serializeHostKeyType(ECDHKeyExchangeReplyMessage msg) {
        appendString(msg.getHostKeyType().getValue());
        LOGGER.debug("HostKeyType: " + msg.getHostKeyType().getValue());
    }

    private void serializeExponentLength(ECDHKeyExchangeReplyMessage msg) {
        appendInt(msg.getHostKeyRsaExponentLength().getValue(), BinaryPacketConstants.LENGTH_FIELD_LENGTH);
        LOGGER.debug("ExponentLength: " + msg.getHostKeyRsaExponentLength().getValue());
    }

    private void serializeExponent(ECDHKeyExchangeReplyMessage msg) {
        appendBytes(msg.getHostKeyRsaExponent().getValue().toByteArray());
        LOGGER.debug("Exponent: " + msg.getHostKeyRsaExponent());
    }

    private void serializeModulusLength(ECDHKeyExchangeReplyMessage msg) {
        appendInt(msg.getHostKeyRsaModulusLength().getValue(), BinaryPacketConstants.LENGTH_FIELD_LENGTH);
        LOGGER.debug("ModulusLength: " + msg.getHostKeyRsaModulusLength().getValue());
    }

    private void serializeModulus(ECDHKeyExchangeReplyMessage msg) {
        appendBytes(msg.getHostKeyRsaModulus().getValue().toByteArray());
        LOGGER.debug("Modulus: " + msg.getHostKeyRsaModulus());
    }

    private void serializeEccCurveIdentifierLength(ECDHKeyExchangeReplyMessage msg) {
        appendInt(msg.getEccCurveIdentifierLength().getValue(), BinaryPacketConstants.LENGTH_FIELD_LENGTH);
        LOGGER.debug("EccCurveIdentifierLength: " + msg.getEccCurveIdentifierLength().getValue());
    }

    private void serializeEccCurveIdentifier(ECDHKeyExchangeReplyMessage msg) {
        appendString(msg.getEccCurveIdentifier().getValue());
        LOGGER.debug("EccCurveIdentifier: " + msg.getEccCurveIdentifier().getValue());
    }

    private void serializeHostKeyEccLength(ECDHKeyExchangeReplyMessage msg) {
        appendInt(msg.getHostKeyEccLength().getValue(), BinaryPacketConstants.LENGTH_FIELD_LENGTH);
        LOGGER.debug("HostKeyEccLength: " + msg.getHostKeyEccLength().getValue());
    }

    private void serializeHostKeyEcc(ECDHKeyExchangeReplyMessage msg) {
        appendBytes(msg.getHostKeyEcc().getValue());
        LOGGER.debug("HostKeyEcc: " + msg.getHostKeyEcc());
    }

    private void serializePublicKeyLength(ECDHKeyExchangeReplyMessage msg) {
        appendInt(msg.getEphemeralPublicKeyLength().getValue(), BinaryPacketConstants.LENGTH_FIELD_LENGTH);
        LOGGER.debug("PublicKeyLength: " + msg.getEphemeralPublicKeyLength().getValue());
    }

    private void serializePublicKey(ECDHKeyExchangeReplyMessage msg) {
        appendBytes(msg.getEphemeralPublicKey().getValue());
        LOGGER.debug("PublicKey: " + msg.getEphemeralPublicKey());
    }

    private void serializeSignatureLength(ECDHKeyExchangeReplyMessage msg) {
        appendInt(msg.getSignatureLength().getValue(), BinaryPacketConstants.LENGTH_FIELD_LENGTH);
        LOGGER.debug("SignatureLength: " + msg.getSignatureLength().getValue());
    }

    private void serializeSignature(ECDHKeyExchangeReplyMessage msg) {
        appendBytes(msg.getSignature().getValue());
        LOGGER.debug("Signature: " + msg.getSignature());
    }

    @Override
    public byte[] serializeMessageSpecificPayload() {
        serializeHostKeyLength(msg);
        serializeHostKeyTypeLength(msg);
        serializeHostKeyType(msg);

        if (msg.getHostKeyType().getValue().equals("ssh-rsa")) {
            serializeHostKeyRsa();
        } else {
            serializeHostKeyEcc(); // TODO better conditions

        }

        serializePublicKeyLength(msg);
        serializePublicKey(msg);
        serializeSignatureLength(msg);
        serializeSignature(msg);
        return getAlreadySerialized();
    }

    private void serializeHostKeyRsa() {
        serializeExponentLength(msg);
        serializeExponent(msg);
        serializeModulusLength(msg);
        serializeModulus(msg);
    }

    private void serializeHostKeyEcc() {
        serializeEccCurveIdentifierLength(msg);
        serializeEccCurveIdentifier(msg);
        serializeHostKeyEccLength(msg);
        serializeHostKeyEcc(msg);
    }
}
