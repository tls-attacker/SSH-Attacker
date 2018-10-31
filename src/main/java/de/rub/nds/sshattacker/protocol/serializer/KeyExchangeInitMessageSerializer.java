package de.rub.nds.sshattacker.protocol.serializer;

import de.rub.nds.protocol.core.message.Serializer;
import de.rub.nds.sshattacker.constants.BinaryPacketConstants;
import de.rub.nds.sshattacker.protocol.message.KeyExchangeInitMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class KeyExchangeInitMessageSerializer extends BinaryPacketSerializer<KeyExchangeInitMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final KeyExchangeInitMessage msg;

    public KeyExchangeInitMessageSerializer(KeyExchangeInitMessage msg) {
        super(msg);
        this.msg = msg;
    }

    private void serializeCookie() {
        LOGGER.debug("Cookie: " + msg.getCookie());
        appendBytes(msg.getCookie().getValue());
    }

    private void serializeKeyExchangeAlgorithmsLength() {
        LOGGER.debug("KeyExchangeAlgorithmsLength: " + msg.getKeyExchangeAlgorithmsLength().getValue());
        appendInt(msg.getKeyExchangeAlgorithmsLength().getValue(), BinaryPacketConstants.LENGTH_FIELD_LENGTH);
    }

    private void serializeKeyExchangeAlgorithms() {
        LOGGER.debug("KeyExchangeAlgorithms: " + msg.getKeyExchangeAlgorithms().getValue());
        appendString(msg.getKeyExchangeAlgorithms().getValue());
    }

    private void serializeServerHostKeyAlgorithmsLength() {
        LOGGER.debug("ServerHostKeyAlgorithmsLength: " + msg.getServerHostKeyAlgorithmsLength().getValue());
        appendInt(msg.getServerHostKeyAlgorithmsLength().getValue(), BinaryPacketConstants.LENGTH_FIELD_LENGTH);
    }

    private void serializeServerHostKeyAlgorithms() {
        LOGGER.debug("ServerHostKeyAlgorithms: " + msg.getServerHostKeyAlgorithms().getValue());
        appendString(msg.getServerHostKeyAlgorithms().getValue());
    }

    private void serializeEncryptionAlgorithmsClientToServerLength() {
        LOGGER.debug("EncryptionAlgorithmsClientToServerLength" + msg.getEncryptionAlgorithmsClientToServerLength().getValue());
        appendInt(msg.getEncryptionAlgorithmsClientToServerLength().getValue(), BinaryPacketConstants.LENGTH_FIELD_LENGTH);
    }

    private void serializeEncryptionAlgorithmsClientToServer() {
        LOGGER.debug("EncryptionAlgorithmsClientToServer: " + msg.getEncryptionAlgorithmsClientToServer().getValue());
        appendString(msg.getEncryptionAlgorithmsClientToServer().getValue());
    }

    private void serializeEncryptionAlgorithmsServerToClientLength() {
        LOGGER.debug("EncryptionAlgorithmsServerToClientLength: " + msg.getEncryptionAlgorithmsServerToClientLength().getValue());
        appendInt(msg.getEncryptionAlgorithmsServerToClientLength().getValue(), BinaryPacketConstants.LENGTH_FIELD_LENGTH);
    }

    private void serializeEncryptionAlgorithmsServerToClient() {
        LOGGER.debug("EncryptionAlgorithmsServerToClient: " + msg.getEncryptionAlgorithmsServerToClient().getValue());
        appendString(msg.getEncryptionAlgorithmsServerToClient().getValue());
    }

    private void serializeMacAlgorithmsClientToServerLength() {
        LOGGER.debug("MacAlgorithmsClientToServerLength: " + msg.getMacAlgorithmsClientToServerLength().getValue());
        appendInt(msg.getMacAlgorithmsClientToServerLength().getValue(), BinaryPacketConstants.LENGTH_FIELD_LENGTH);
    }

    private void serializeMacAlgorithmsClientToServer() {
        LOGGER.debug("MacAlgorithmsClientToServer: " + msg.getMacAlgorithmsClientToServer().getValue());
        appendString(msg.getMacAlgorithmsClientToServer().getValue());
    }

    private void serializeMacAlgorithmsServerToClientLength() {
        LOGGER.debug("MacAlgorithmsServerToClientLength: " + msg.getMacAlgorithmsServerToClientLength().getValue());
        appendInt(msg.getMacAlgorithmsServerToClientLength().getValue(), BinaryPacketConstants.LENGTH_FIELD_LENGTH);
    }

    private void serializeMacAlgorithmsServerToClient() {
        LOGGER.debug("MacAlgorithmsServerToClient: " + msg.getMacAlgorithmsServerToClient().getValue());
        appendString(msg.getMacAlgorithmsServerToClient().getValue());
    }

    private void serializeCompressionAlgorithmsClientToServerLength() {
        LOGGER.debug("CompressionAlgorithmsClientToServerLength: " + msg.getCompressionAlgorithmsClientToServerLength().getValue());
        appendInt(msg.getCompressionAlgorithmsClientToServerLength().getValue(), BinaryPacketConstants.LENGTH_FIELD_LENGTH);
    }

    private void serializeCompressionAlgorithmsClientToServer() {
        LOGGER.debug("CompressionAlgorithmsClientToServer: " + msg.getCompressionAlgorithmsClientToServer().getValue());
        appendString(msg.getCompressionAlgorithmsClientToServer().getValue());
    }

    private void serializeCompressionAlgorithmsServerToClientLength() {
        LOGGER.debug("CompressionAlgorithmsServerToClientLength: " + msg.getCompressionAlgorithmsServerToClientLength().getValue());
        appendInt(msg.getCompressionAlgorithmsServerToClientLength().getValue(), BinaryPacketConstants.LENGTH_FIELD_LENGTH);
    }

    private void serializeCompressionAlgorithmsServerToClient() {
        LOGGER.debug("CompressionAlgorithmsServerToClient: " + msg.getCompressionAlgorithmsServerToClient().getValue());
        appendString(msg.getCompressionAlgorithmsServerToClient().getValue());
    }

    private void serializeLanguagesClientToServerLength() {
        LOGGER.debug("LanguagesClientToServerLength: " + msg.getLanguagesClientToServerLength().getValue());
        appendInt(msg.getLanguagesClientToServerLength().getValue(), BinaryPacketConstants.LENGTH_FIELD_LENGTH);
    }

    private void serializeLanguagesClientToServer() {
        LOGGER.debug("LanguagesClientToServer: " + msg.getLanguagesClientToServer().getValue());
        appendString(msg.getLanguagesClientToServer().getValue());
    }

    private void serializeLanguagesServerToClientLength() {
        LOGGER.debug("LanguagesServerToClientLength: " + msg.getLanguagesServerToClientLength().getValue());
        appendInt(msg.getLanguagesServerToClientLength().getValue(), BinaryPacketConstants.LENGTH_FIELD_LENGTH);
    }

    private void serializeLanguagesServerToClient() {
        LOGGER.debug("LanguagesServerToClient: " + msg.getLanguagesServerToClient().getValue());
        appendString(msg.getLanguagesServerToClient().getValue());
    }

    private void serializeFirstKeyExchangePacketFollows() {
        LOGGER.debug("FirstKeyExchangePacketFollows: " + msg.getFirstKeyExchangePacketFollows().getValue());
        appendByte(msg.getFirstKeyExchangePacketFollows().getValue());
    }

    private void serializeReserved() {
        LOGGER.debug("Reserved: " + msg.getReserved().getValue());
        appendInt(msg.getReserved().getValue(), BinaryPacketConstants.LENGTH_FIELD_LENGTH);
    }

    @Override
    protected byte[] serializeMessageSpecificPayload() {
        serializeCookie();
        serializeKeyExchangeAlgorithmsLength();
        serializeKeyExchangeAlgorithms();
        serializeServerHostKeyAlgorithmsLength();
        serializeServerHostKeyAlgorithms();
        serializeEncryptionAlgorithmsClientToServerLength();
        serializeEncryptionAlgorithmsClientToServer();
        serializeEncryptionAlgorithmsServerToClientLength();
        serializeEncryptionAlgorithmsServerToClient();
        serializeMacAlgorithmsClientToServerLength();
        serializeMacAlgorithmsClientToServer();
        serializeMacAlgorithmsServerToClientLength();
        serializeMacAlgorithmsServerToClient();
        serializeCompressionAlgorithmsClientToServerLength();
        serializeCompressionAlgorithmsClientToServer();
        serializeCompressionAlgorithmsServerToClientLength();
        serializeCompressionAlgorithmsServerToClient();
        serializeLanguagesClientToServerLength();
        serializeLanguagesClientToServer();
        serializeLanguagesServerToClientLength();
        serializeLanguagesServerToClient();
        serializeFirstKeyExchangePacketFollows();
        serializeReserved();
        return getAlreadySerialized();
    }
}
