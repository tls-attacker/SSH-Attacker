/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.authentication.handler;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.PublicKeyAlgorithm;
import de.rub.nds.sshattacker.core.crypto.keys.SshPublicKey;
import de.rub.nds.sshattacker.core.crypto.signature.RawSignature;
import de.rub.nds.sshattacker.core.crypto.signature.SignatureFactory;
import de.rub.nds.sshattacker.core.crypto.signature.SignatureParser;
import de.rub.nds.sshattacker.core.crypto.signature.VerifyingSignature;
import de.rub.nds.sshattacker.core.crypto.util.PublicKeyHelper;
import de.rub.nds.sshattacker.core.exceptions.CryptoException;
import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthHostbasedMessage;
import de.rub.nds.sshattacker.core.protocol.authentication.parser.UserAuthHostbasedMessageParser;
import de.rub.nds.sshattacker.core.protocol.authentication.preparator.UserAuthHostbasedMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.authentication.serializer.UserAuthHostbasedMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.util.Converter;
import java.nio.charset.StandardCharsets;

public class UserAuthHostbasedMessageHandler extends SshMessageHandler<UserAuthHostbasedMessage> {

    public UserAuthHostbasedMessageHandler(SshContext context) {
        super(context);
    }

    public UserAuthHostbasedMessageHandler(SshContext context, UserAuthHostbasedMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {
        checkSignature();
    }

    public void checkSignature() {
        if (message.getHostKeyBytes() != null && message.getHostKeyBytes().getValue() != null) {
            PublicKeyAlgorithm hostKeyAlgorithm =
                    PublicKeyAlgorithm.fromName(message.getPubKeyAlgorithm().getValue());
            SshPublicKey<?, ?> hostKey =
                    PublicKeyHelper.parse(
                            hostKeyAlgorithm.getKeyFormat(), message.getHostKeyBytes().getValue());

            RawSignature signature =
                    new SignatureParser(message.getSignature().getValue(), 0).parse();
            try {
                VerifyingSignature verifyingSignature =
                        SignatureFactory.getVerifyingSignature(hostKeyAlgorithm, hostKey);
                if (verifyingSignature.verify(
                        prepareSignatureInput(), signature.getSignatureBytes())) {
                    LOGGER.info("Signature verification successful: Signature is valid.");
                } else {
                    LOGGER.warn(
                            "Signature verification failed: Signature is invalid - continuing anyway.");
                }
            } catch (CryptoException e) {
                LOGGER.error(
                        "Signature verification failed: Unexpected cryptographic error - see debug for more details.");
                LOGGER.debug(e);
            }
        } else {
            LOGGER.error("Signature verification failed: Client host key missing.");
        }
    }

    public byte[] prepareSignatureInput() {
        return ArrayConverter.concatenate(
                Converter.bytesToLengthPrefixedBinaryString(
                        context.getSessionID().orElse(new byte[] {})),
                new byte[] {message.getMessageId().getValue()},
                Converter.stringToLengthPrefixedBinaryString(message.getUserName().getValue()),
                Converter.stringToLengthPrefixedBinaryString(message.getServiceName().getValue()),
                Converter.stringToLengthPrefixedBinaryString(message.getMethodName().getValue()),
                Converter.stringToLengthPrefixedBinaryString(
                        message.getPubKeyAlgorithm().getValue()),
                Converter.bytesToLengthPrefixedBinaryString(message.getHostKeyBytes().getValue()),
                Converter.stringToLengthPrefixedBinaryString(message.getHostName().getValue()),
                Converter.bytesToLengthPrefixedBinaryString(
                        message.getClientUserName().getValue().getBytes(StandardCharsets.UTF_8)));
    }

    @Override
    public UserAuthHostbasedMessageParser getParser(byte[] array) {
        return new UserAuthHostbasedMessageParser(array);
    }

    @Override
    public UserAuthHostbasedMessageParser getParser(byte[] array, int startPosition) {
        return new UserAuthHostbasedMessageParser(array, startPosition);
    }

    public static final UserAuthHostbasedMessagePreparator PREPARATOR =
            new UserAuthHostbasedMessagePreparator();

    public static final UserAuthHostbasedMessageSerializer SERIALIZER =
            new UserAuthHostbasedMessageSerializer();
}
