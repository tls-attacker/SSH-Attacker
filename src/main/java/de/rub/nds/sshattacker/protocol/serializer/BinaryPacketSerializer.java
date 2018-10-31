package de.rub.nds.sshattacker.protocol.serializer;

import de.rub.nds.protocol.core.message.Serializer;
import de.rub.nds.sshattacker.constants.BinaryPacketConstants;
import de.rub.nds.sshattacker.protocol.message.BinaryPacket;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class BinaryPacketSerializer<T extends BinaryPacket> extends Serializer<T> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final BinaryPacket msg;

    public BinaryPacketSerializer(T msg) {
        this.msg = msg;
    }

    private void serializeMessageID() {
        LOGGER.debug("MessageID: " + msg.getMessageID().getValue());
        appendByte(msg.getMessageID().getValue());
    }

    private void serializePacketLength() {
        LOGGER.debug("Packet Length: " + msg.getPacketLength().getValue());
        appendInt(msg.getPacketLength().getValue(), BinaryPacketConstants.LENGTH_FIELD_LENGTH);
    }

    private void serializePaddingLength() {
        LOGGER.debug("Padding Length: " + msg.getPaddingLength().getValue());
        appendByte(msg.getPaddingLength().getValue());
    }

    private void serializePayload() {
        LOGGER.debug("Payload: " + msg.getPayload());
        appendBytes(msg.getPayload().getValue());
    }

    private void serializePadding() {
        LOGGER.debug("Padding: " + msg.getPadding());
        appendBytes(msg.getPadding().getValue());
    }

    private void serializeMac() {
        if (msg.getMac().getValue() == null) {
            LOGGER.debug("MAC: none");
        } else {
            LOGGER.debug("MAC: " + msg.getMac());
            appendBytes(msg.getMac().getValue());
        }
    }

    @Override
    public byte[] serializeBytes() {
        serializePacketLength();
        serializePaddingLength();
        serializeMessageID();
        appendBytes(serializeMessageSpecificPayload());
        serializePadding();
        serializeMac();
        return getAlreadySerialized();
    }

    protected abstract byte[] serializeMessageSpecificPayload();
}
