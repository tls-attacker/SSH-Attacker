/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.authentication.serializer;

import static de.rub.nds.modifiablevariable.util.StringUtil.backslashEscapeString;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthHostbasedMessage;
import de.rub.nds.sshattacker.core.protocol.common.SerializerStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class UserAuthHostbasedMessageSerializer
        extends UserAuthRequestMessageSerializer<UserAuthHostbasedMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private static void serializePubKeyAlgorithm(
            UserAuthHostbasedMessage object, SerializerStream output) {
        Integer pubKeyAlgorithmLength = object.getPubKeyAlgorithmLength().getValue();
        LOGGER.debug("Public key algorithm length: {}", pubKeyAlgorithmLength);
        output.appendInt(pubKeyAlgorithmLength);
        String pubKeyAlgorithm = object.getPubKeyAlgorithm().getValue();
        LOGGER.debug("Public key algorithm: {}", () -> backslashEscapeString(pubKeyAlgorithm));
        output.appendString(pubKeyAlgorithm);
    }

    private static void serializeHostKeyBytes(
            UserAuthHostbasedMessage object, SerializerStream output) {
        Integer hostKeyBytesLength = object.getHostKeyBytesLength().getValue();
        LOGGER.debug("Host key length: {}", hostKeyBytesLength);
        output.appendInt(hostKeyBytesLength);
        byte[] hostKeyBytes = object.getHostKeyBytes().getValue();
        LOGGER.debug("Host key: {}", () -> ArrayConverter.bytesToRawHexString(hostKeyBytes));
        output.appendBytes(hostKeyBytes);
    }

    private static void serializeHostName(
            UserAuthHostbasedMessage object, SerializerStream output) {
        Integer hostNameLength = object.getHostNameLength().getValue();
        LOGGER.debug("Host name length: {}", hostNameLength);
        output.appendInt(hostNameLength);
        String hostName = object.getHostName().getValue();
        LOGGER.debug("Host name: {}", () -> backslashEscapeString(hostName));
        output.appendString(hostName);
    }

    private static void serializeClientUserName(
            UserAuthHostbasedMessage object, SerializerStream output) {
        Integer clientUserNameLength = object.getClientUserNameLength().getValue();
        LOGGER.debug("Client user name length: {}", clientUserNameLength);
        output.appendInt(clientUserNameLength);
        String clientUserName = object.getClientUserName().getValue();
        LOGGER.debug("Client user name: {}", () -> backslashEscapeString(clientUserName));
        output.appendString(clientUserName);
    }

    private static void serializeSignature(
            UserAuthHostbasedMessage object, SerializerStream output) {
        Integer signatureLength = object.getSignatureLength().getValue();
        LOGGER.debug("Signature length: {}", signatureLength);
        output.appendInt(signatureLength);
        byte[] signature = object.getSignature().getValue();
        LOGGER.debug("Signature: {}", () -> ArrayConverter.bytesToRawHexString(signature));
        output.appendBytes(signature);
    }

    @Override
    protected void serializeMessageSpecificContents(
            UserAuthHostbasedMessage object, SerializerStream output) {
        super.serializeMessageSpecificContents(object, output);
        serializePubKeyAlgorithm(object, output);
        serializeHostKeyBytes(object, output);
        serializeHostName(object, output);
        serializeClientUserName(object, output);
        serializeSignature(object, output);
    }
}
