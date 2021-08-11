/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * <p>Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.serializer;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.common.MessageSerializer;
import de.rub.nds.sshattacker.core.protocol.transport.message.KeyExchangeInitMessage;
import de.rub.nds.sshattacker.core.util.Converter;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class KeyExchangeInitMessageSerializer extends MessageSerializer<KeyExchangeInitMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public KeyExchangeInitMessageSerializer(KeyExchangeInitMessage msg) {
        super(msg);
    }

    private void serializeCookie() {
        LOGGER.debug("Cookie: " + msg.getCookie());
        appendBytes(msg.getCookie().getValue());
    }

    private void serializeKeyExchangeAlgorithms() {
        LOGGER.debug("Key exchange algorithms: " + msg.getKeyExchangeAlgorithmsLength().getValue());
        appendInt(
                msg.getKeyExchangeAlgorithmsLength().getValue(),
                DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug("Key exchange algorithms: " + msg.getKeyExchangeAlgorithms().getValue());
        appendString(msg.getKeyExchangeAlgorithms().getValue(), StandardCharsets.US_ASCII);
    }

    private void serializeServerHostKeyAlgorithms() {
        LOGGER.debug(
                "Server host key algorithms: " + msg.getServerHostKeyAlgorithmsLength().getValue());
        appendInt(
                msg.getServerHostKeyAlgorithmsLength().getValue(),
                DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug("Server host key algorithms: " + msg.getServerHostKeyAlgorithms().getValue());
        appendString(msg.getServerHostKeyAlgorithms().getValue(), StandardCharsets.US_ASCII);
    }

    private void serializeEncryptionAlgorithmsClientToServer() {
        LOGGER.debug(
                "Encryption algorithms length (client to server): "
                        + msg.getEncryptionAlgorithmsClientToServerLength().getValue());
        appendInt(
                msg.getEncryptionAlgorithmsClientToServerLength().getValue(),
                DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug(
                "Encryption algorithms (client to server): "
                        + msg.getEncryptionAlgorithmsClientToServer().getValue());
        appendString(
                msg.getEncryptionAlgorithmsClientToServer().getValue(), StandardCharsets.US_ASCII);
    }

    private void serializeEncryptionAlgorithmsServerToClient() {
        LOGGER.debug(
                "Encryption algorithms length (server to client): "
                        + msg.getEncryptionAlgorithmsServerToClientLength().getValue());
        appendInt(
                msg.getEncryptionAlgorithmsServerToClientLength().getValue(),
                DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug(
                "Encryption algorithms (server to client): "
                        + msg.getEncryptionAlgorithmsServerToClient().getValue());
        appendString(
                msg.getEncryptionAlgorithmsServerToClient().getValue(), StandardCharsets.US_ASCII);
    }

    private void serializeMacAlgorithmsClientToServer() {
        LOGGER.debug(
                "MAC algorithms length (client to server): "
                        + msg.getMacAlgorithmsClientToServerLength().getValue());
        appendInt(
                msg.getMacAlgorithmsClientToServerLength().getValue(),
                DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug(
                "MAC algorithms (client to server): "
                        + msg.getMacAlgorithmsClientToServer().getValue());
        appendString(msg.getMacAlgorithmsClientToServer().getValue(), StandardCharsets.US_ASCII);
    }

    private void serializeMacAlgorithmsServerToClient() {
        LOGGER.debug(
                "MAC algorithms length (server to client): "
                        + msg.getMacAlgorithmsServerToClientLength().getValue());
        appendInt(
                msg.getMacAlgorithmsServerToClientLength().getValue(),
                DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug(
                "MAC algorithms (server to client): "
                        + msg.getMacAlgorithmsServerToClient().getValue());
        appendString(msg.getMacAlgorithmsServerToClient().getValue(), StandardCharsets.US_ASCII);
    }

    private void serializeCompressionAlgorithmsClientToServer() {
        LOGGER.debug(
                "Compression algorithms length (client to server): "
                        + msg.getCompressionAlgorithmsClientToServerLength().getValue());
        appendInt(
                msg.getCompressionAlgorithmsClientToServerLength().getValue(),
                DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug(
                "Compression algorithms (client to server): "
                        + msg.getCompressionAlgorithmsClientToServer().getValue());
        appendString(
                msg.getCompressionAlgorithmsClientToServer().getValue(), StandardCharsets.US_ASCII);
    }

    private void serializeCompressionAlgorithmsServerToClient() {
        LOGGER.debug(
                "Compression algorithms length (server to client): "
                        + msg.getCompressionAlgorithmsServerToClientLength().getValue());
        appendInt(
                msg.getCompressionAlgorithmsServerToClientLength().getValue(),
                DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug(
                "Compression algorithms (server to client): "
                        + msg.getCompressionAlgorithmsServerToClient().getValue());
        appendString(
                msg.getCompressionAlgorithmsServerToClient().getValue(), StandardCharsets.US_ASCII);
    }

    private void serializeLanguagesClientToServer() {
        LOGGER.debug(
                "Languages length (client to server): "
                        + msg.getLanguagesClientToServerLength().getValue());
        appendInt(
                msg.getLanguagesClientToServerLength().getValue(),
                DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug(
                "Languages (client to server): " + msg.getLanguagesClientToServer().getValue());
        appendString(msg.getLanguagesClientToServer().getValue(), StandardCharsets.US_ASCII);
    }

    private void serializeLanguagesServerToClient() {
        LOGGER.debug(
                "Languages length (server to client): "
                        + msg.getLanguagesServerToClientLength().getValue());
        appendInt(
                msg.getLanguagesServerToClientLength().getValue(),
                DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug(
                "Languages (server to client): " + msg.getLanguagesServerToClient().getValue());
        appendString(msg.getLanguagesServerToClient().getValue(), StandardCharsets.US_ASCII);
    }

    private void serializeFirstKeyExchangePacketFollows() {
        LOGGER.debug(
                "First key exchange packet follows: "
                        + Converter.byteToBoolean(
                                msg.getFirstKeyExchangePacketFollows().getValue()));
        appendByte(msg.getFirstKeyExchangePacketFollows().getValue());
    }

    private void serializeReserved() {
        LOGGER.debug("Reserved: " + msg.getReserved().getValue());
        appendInt(msg.getReserved().getValue(), DataFormatConstants.INT32_SIZE);
    }

    @Override
    public void serializeMessageSpecificPayload() {
        serializeCookie();
        serializeKeyExchangeAlgorithms();
        serializeServerHostKeyAlgorithms();
        serializeEncryptionAlgorithmsClientToServer();
        serializeEncryptionAlgorithmsServerToClient();
        serializeMacAlgorithmsClientToServer();
        serializeMacAlgorithmsServerToClient();
        serializeCompressionAlgorithmsClientToServer();
        serializeCompressionAlgorithmsServerToClient();
        serializeLanguagesClientToServer();
        serializeLanguagesServerToClient();
        serializeFirstKeyExchangePacketFollows();
        serializeReserved();
    }
}
