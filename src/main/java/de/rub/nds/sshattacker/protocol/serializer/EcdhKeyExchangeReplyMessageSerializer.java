package de.rub.nds.sshattacker.protocol.serializer;

import de.rub.nds.sshattacker.constants.BinaryPacketConstants;
import de.rub.nds.sshattacker.protocol.message.EcdhKeyExchangeReplyMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class EcdhKeyExchangeReplyMessageSerializer extends MessageSerializer<EcdhKeyExchangeReplyMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public EcdhKeyExchangeReplyMessageSerializer(EcdhKeyExchangeReplyMessage msg) {
        super(msg);
        this.msg = msg;
    }

    private final EcdhKeyExchangeReplyMessage msg;

    private void serializeHostKeyLength(EcdhKeyExchangeReplyMessage msg) {
        appendInt(msg.getHostKeyLength().getValue(), BinaryPacketConstants.LENGTH_FIELD_LENGTH);
        LOGGER.debug("HostKeyLength: " + msg.getHostKeyLength().getValue());
    }

    private void serializeHostKeyTypeLength(EcdhKeyExchangeReplyMessage msg) {
        appendInt(msg.getHostKeyTypeLength().getValue(), BinaryPacketConstants.LENGTH_FIELD_LENGTH);
        LOGGER.debug("HostKeyTypeLength: " + msg.getHostKeyTypeLength().getValue());
    }

    private void serializeHostKeyType(EcdhKeyExchangeReplyMessage msg) {
        appendString(msg.getHostKeyType().getValue());
        LOGGER.debug("HostKeyType: " + msg.getHostKeyType().getValue());
    }

    private void serializeExponentLength(EcdhKeyExchangeReplyMessage msg) {
        appendInt(msg.getHostKeyRsaExponentLength().getValue(), BinaryPacketConstants.LENGTH_FIELD_LENGTH);
        LOGGER.debug("ExponentLength: " + msg.getHostKeyRsaExponentLength().getValue());
    }

    private void serializeExponent(EcdhKeyExchangeReplyMessage msg) {
        appendBytes(msg.getHostKeyRsaExponent().getValue().toByteArray());
        LOGGER.debug("Exponent: " + msg.getHostKeyRsaExponent());
    }

    private void serializeModulusLength(EcdhKeyExchangeReplyMessage msg) {
        appendInt(msg.getHostKeyRsaModulusLength().getValue(), BinaryPacketConstants.LENGTH_FIELD_LENGTH);
        LOGGER.debug("ModulusLength: " + msg.getHostKeyRsaModulusLength().getValue());
    }

    private void serializeModulus(EcdhKeyExchangeReplyMessage msg) {
        appendBytes(msg.getHostKeyRsaModulus().getValue().toByteArray());
        LOGGER.debug("Modulus: " + msg.getHostKeyRsaModulus());
    }

    private void serializeEccCurveIdentifierLength(EcdhKeyExchangeReplyMessage msg) {
        appendInt(msg.getEccCurveIdentifierLength().getValue(), BinaryPacketConstants.LENGTH_FIELD_LENGTH);
        LOGGER.debug("EccCurveIdentifierLength: " + msg.getEccCurveIdentifierLength().getValue());
    }

    private void serializeEccCurveIdentifier(EcdhKeyExchangeReplyMessage msg) {
        appendString(msg.getEccCurveIdentifier().getValue());
        LOGGER.debug("EccCurveIdentifier: " + msg.getEccCurveIdentifier().getValue());
    }

    private void serializeHostKeyEccLength(EcdhKeyExchangeReplyMessage msg) {
        appendInt(msg.getHostKeyEccLength().getValue(), BinaryPacketConstants.LENGTH_FIELD_LENGTH);
        LOGGER.debug("HostKeyEccLength: " + msg.getHostKeyEccLength().getValue());
    }

    private void serializeHostKeyEcc(EcdhKeyExchangeReplyMessage msg) {
        appendBytes(msg.getHostKeyEcc().getValue());
        LOGGER.debug("HostKeyEcc: " + msg.getHostKeyEcc());
    }

    private void serializePublicKeyLength(EcdhKeyExchangeReplyMessage msg) {
        appendInt(msg.getEphemeralPublicKeyLength().getValue(), BinaryPacketConstants.LENGTH_FIELD_LENGTH);
        LOGGER.debug("PublicKeyLength: " + msg.getEphemeralPublicKeyLength().getValue());
    }

    private void serializePublicKey(EcdhKeyExchangeReplyMessage msg) {
        appendBytes(msg.getEphemeralPublicKey().getValue());
        LOGGER.debug("PublicKey: " + msg.getEphemeralPublicKey());
    }

    private void serializeSignatureLength(EcdhKeyExchangeReplyMessage msg) {
        appendInt(msg.getSignatureLength().getValue(), BinaryPacketConstants.LENGTH_FIELD_LENGTH);
        LOGGER.debug("SignatureLength: " + msg.getSignatureLength().getValue());
    }

    private void serializeSignature(EcdhKeyExchangeReplyMessage msg) {
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
