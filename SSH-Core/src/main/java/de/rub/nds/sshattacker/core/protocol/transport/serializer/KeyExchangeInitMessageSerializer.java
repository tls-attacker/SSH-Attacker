/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.serializer;

import static de.rub.nds.modifiablevariable.util.StringUtil.backslashEscapeString;

import de.rub.nds.sshattacker.core.protocol.common.SerializerStream;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.transport.message.KeyExchangeInitMessage;
import de.rub.nds.sshattacker.core.util.Converter;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class KeyExchangeInitMessageSerializer extends SshMessageSerializer<KeyExchangeInitMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private static void serializeCookie(KeyExchangeInitMessage object, SerializerStream output) {
        LOGGER.debug("Cookie: {}", object.getCookie());
        output.appendBytes(object.getCookie().getValue());
    }

    private static void serializeKeyExchangeAlgorithms(
            KeyExchangeInitMessage object, SerializerStream output) {
        Integer keyExchangeAlgorithmsLength = object.getKeyExchangeAlgorithmsLength().getValue();
        LOGGER.debug("Key exchange algorithms: {}", keyExchangeAlgorithmsLength);
        output.appendInt(keyExchangeAlgorithmsLength);
        String keyExchangeAlgorithms = object.getKeyExchangeAlgorithms().getValue();
        LOGGER.debug(
                "Key exchange algorithms: {}", () -> backslashEscapeString(keyExchangeAlgorithms));
        output.appendString(keyExchangeAlgorithms, StandardCharsets.US_ASCII);
    }

    private static void serializeServerHostKeyAlgorithms(
            KeyExchangeInitMessage object, SerializerStream output) {
        Integer serverHostKeyAlgorithmsLength =
                object.getServerHostKeyAlgorithmsLength().getValue();
        LOGGER.debug("Server host key algorithms: {}", serverHostKeyAlgorithmsLength);
        output.appendInt(serverHostKeyAlgorithmsLength);
        String serverHostKeyAlgorithms = object.getServerHostKeyAlgorithms().getValue();
        LOGGER.debug(
                "Server host key algorithms: {}",
                () -> backslashEscapeString(serverHostKeyAlgorithms));
        output.appendString(serverHostKeyAlgorithms, StandardCharsets.US_ASCII);
    }

    private static void serializeEncryptionAlgorithmsClientToServer(
            KeyExchangeInitMessage object, SerializerStream output) {
        Integer encryptionAlgorithmsClientToServerLength =
                object.getEncryptionAlgorithmsClientToServerLength().getValue();
        LOGGER.debug(
                "Encryption algorithms length (client to server): {}",
                encryptionAlgorithmsClientToServerLength);
        output.appendInt(encryptionAlgorithmsClientToServerLength);
        String encryptionAlgorithmsClientToServer =
                object.getEncryptionAlgorithmsClientToServer().getValue();
        LOGGER.debug(
                "Encryption algorithms (client to server): {}",
                () -> backslashEscapeString(encryptionAlgorithmsClientToServer));
        output.appendString(encryptionAlgorithmsClientToServer, StandardCharsets.US_ASCII);
    }

    private static void serializeEncryptionAlgorithmsServerToClient(
            KeyExchangeInitMessage object, SerializerStream output) {
        Integer encryptionAlgorithmsServerToClientLength =
                object.getEncryptionAlgorithmsServerToClientLength().getValue();
        LOGGER.debug(
                "Encryption algorithms length (server to client): {}",
                encryptionAlgorithmsServerToClientLength);
        output.appendInt(encryptionAlgorithmsServerToClientLength);
        String encryptionAlgorithmsServerToClient =
                object.getEncryptionAlgorithmsServerToClient().getValue();
        LOGGER.debug(
                "Encryption algorithms (server to client): {}",
                () -> backslashEscapeString(encryptionAlgorithmsServerToClient));
        output.appendString(encryptionAlgorithmsServerToClient, StandardCharsets.US_ASCII);
    }

    private static void serializeMacAlgorithmsClientToServer(
            KeyExchangeInitMessage object, SerializerStream output) {
        Integer macAlgorithmsClientToServerLength =
                object.getMacAlgorithmsClientToServerLength().getValue();
        LOGGER.debug(
                "MAC algorithms length (client to server): {}", macAlgorithmsClientToServerLength);
        output.appendInt(macAlgorithmsClientToServerLength);
        String macAlgorithmsClientToServer = object.getMacAlgorithmsClientToServer().getValue();
        LOGGER.debug(
                "MAC algorithms (client to server): {}",
                () -> backslashEscapeString(macAlgorithmsClientToServer));
        output.appendString(macAlgorithmsClientToServer, StandardCharsets.US_ASCII);
    }

    private static void serializeMacAlgorithmsServerToClient(
            KeyExchangeInitMessage object, SerializerStream output) {
        Integer macAlgorithmsServerToClientLength =
                object.getMacAlgorithmsServerToClientLength().getValue();
        LOGGER.debug(
                "MAC algorithms length (server to client): {}", macAlgorithmsServerToClientLength);
        output.appendInt(macAlgorithmsServerToClientLength);
        String macAlgorithmsServerToClient = object.getMacAlgorithmsServerToClient().getValue();
        LOGGER.debug(
                "MAC algorithms (server to client): {}",
                () -> backslashEscapeString(macAlgorithmsServerToClient));
        output.appendString(macAlgorithmsServerToClient, StandardCharsets.US_ASCII);
    }

    private static void serializeCompressionMethodsClientToServer(
            KeyExchangeInitMessage object, SerializerStream output) {
        Integer compressionMethodsClientToServerLength =
                object.getCompressionMethodsClientToServerLength().getValue();
        LOGGER.debug(
                "Compression algorithms length (client to server): {}",
                compressionMethodsClientToServerLength);
        output.appendInt(compressionMethodsClientToServerLength);
        String compressionMethodsClientToServer =
                object.getCompressionMethodsClientToServer().getValue();
        LOGGER.debug(
                "Compression algorithms (client to server): {}",
                () -> backslashEscapeString(compressionMethodsClientToServer));
        output.appendString(compressionMethodsClientToServer, StandardCharsets.US_ASCII);
    }

    private static void serializeCompressionMethodsServerToClient(
            KeyExchangeInitMessage object, SerializerStream output) {
        Integer compressionMethodsServerToClientLength =
                object.getCompressionMethodsServerToClientLength().getValue();
        LOGGER.debug(
                "Compression algorithms length (server to client): {}",
                compressionMethodsServerToClientLength);
        output.appendInt(compressionMethodsServerToClientLength);
        String compressionMethodsServerToClient =
                object.getCompressionMethodsServerToClient().getValue();
        LOGGER.debug(
                "Compression algorithms (server to client): {}",
                () -> backslashEscapeString(compressionMethodsServerToClient));
        output.appendString(compressionMethodsServerToClient, StandardCharsets.US_ASCII);
    }

    private static void serializeLanguagesClientToServer(
            KeyExchangeInitMessage object, SerializerStream output) {
        Integer languagesClientToServerLength =
                object.getLanguagesClientToServerLength().getValue();
        LOGGER.debug("Languages length (client to server): {}", languagesClientToServerLength);
        output.appendInt(languagesClientToServerLength);
        String languagesClientToServer = object.getLanguagesClientToServer().getValue();
        LOGGER.debug(
                "Languages (client to server): {}",
                () -> backslashEscapeString(languagesClientToServer));
        output.appendString(languagesClientToServer, StandardCharsets.US_ASCII);
    }

    private static void serializeLanguagesServerToClient(
            KeyExchangeInitMessage object, SerializerStream output) {
        Integer languagesServerToClientLength =
                object.getLanguagesServerToClientLength().getValue();
        LOGGER.debug("Languages length (server to client): {}", languagesServerToClientLength);
        output.appendInt(languagesServerToClientLength);
        String languagesServerToClient = object.getLanguagesServerToClient().getValue();
        LOGGER.debug(
                "Languages (server to client): {}",
                () -> backslashEscapeString(languagesServerToClient));
        output.appendString(languagesServerToClient, StandardCharsets.US_ASCII);
    }

    private static void serializeFirstKeyExchangePacketFollows(
            KeyExchangeInitMessage object, SerializerStream output) {
        Byte firstKeyExchangePacketFollows = object.getFirstKeyExchangePacketFollows().getValue();
        LOGGER.debug(
                "First key exchange packet follows: {}",
                () -> Converter.byteToBoolean(firstKeyExchangePacketFollows));
        output.appendByte(firstKeyExchangePacketFollows);
    }

    private static void serializeReserved(KeyExchangeInitMessage object, SerializerStream output) {
        Integer reserved = object.getReserved().getValue();
        LOGGER.debug("Reserved: {}", reserved);
        output.appendInt(reserved);
    }

    @Override
    protected void serializeMessageSpecificContents(
            KeyExchangeInitMessage object, SerializerStream output) {
        serializeCookie(object, output);
        serializeKeyExchangeAlgorithms(object, output);
        serializeServerHostKeyAlgorithms(object, output);
        serializeEncryptionAlgorithmsClientToServer(object, output);
        serializeEncryptionAlgorithmsServerToClient(object, output);
        serializeMacAlgorithmsClientToServer(object, output);
        serializeMacAlgorithmsServerToClient(object, output);
        serializeCompressionMethodsClientToServer(object, output);
        serializeCompressionMethodsServerToClient(object, output);
        serializeLanguagesClientToServer(object, output);
        serializeLanguagesServerToClient(object, output);
        serializeFirstKeyExchangePacketFollows(object, output);
        serializeReserved(object, output);
    }
}
