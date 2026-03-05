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
import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthRequestHostbasedMessage;
import de.rub.nds.sshattacker.core.protocol.authentication.parser.UserAuthRequestHostbasedMessageParser;
import de.rub.nds.sshattacker.core.protocol.authentication.preparator.UserAuthRequestHostbasedMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.authentication.serializer.UserAuthRequestHostbasedMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.util.Converter;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class UserAuthRequestHostbasedMessageHandler
        extends SshMessageHandler<UserAuthRequestHostbasedMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    @Override
    public void adjustContext(SshContext context, UserAuthRequestHostbasedMessage object) {
        checkSignature(context, object);
    }

    public static void checkSignature(SshContext context, UserAuthRequestHostbasedMessage object) {
        if (object.getHostKeyBytes() != null && object.getHostKeyBytes().getValue() != null) {
            PublicKeyAlgorithm hostKeyAlgorithm =
                    PublicKeyAlgorithm.fromName(object.getPubKeyAlgorithm().getValue());
            SshPublicKey<?, ?> hostKey =
                    PublicKeyHelper.parse(
                            hostKeyAlgorithm.getKeyFormat(), object.getHostKeyBytes().getValue());

            RawSignature signature =
                    new SignatureParser(object.getSignature().getValue(), 0).parse();
            try {
                VerifyingSignature verifyingSignature =
                        SignatureFactory.getVerifyingSignature(hostKeyAlgorithm, hostKey);
                if (verifyingSignature.verify(
                        prepareSignatureInput(context, object), signature.getSignatureBytes())) {
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

    public static byte[] prepareSignatureInput(
            SshContext context, UserAuthRequestHostbasedMessage object) {
        return ArrayConverter.concatenate(
                Converter.bytesToLengthPrefixedBinaryString(
                        context.getSessionID().orElse(new byte[] {})),
                new byte[] {object.getMessageId().getValue()},
                Converter.stringToLengthPrefixedBinaryString(object.getUserName().getValue()),
                Converter.stringToLengthPrefixedBinaryString(object.getServiceName().getValue()),
                Converter.stringToLengthPrefixedBinaryString(object.getMethodName().getValue()),
                Converter.stringToLengthPrefixedBinaryString(
                        object.getPubKeyAlgorithm().getValue()),
                Converter.bytesToLengthPrefixedBinaryString(object.getHostKeyBytes().getValue()),
                Converter.stringToLengthPrefixedBinaryString(object.getHostName().getValue()),
                Converter.bytesToLengthPrefixedBinaryString(
                        object.getClientUserName().getValue().getBytes(StandardCharsets.UTF_8)));
    }

    @Override
    public UserAuthRequestHostbasedMessageParser getParser(byte[] array, SshContext context) {
        return new UserAuthRequestHostbasedMessageParser(array);
    }

    @Override
    public UserAuthRequestHostbasedMessageParser getParser(
            byte[] array, int startPosition, SshContext context) {
        return new UserAuthRequestHostbasedMessageParser(array, startPosition);
    }

    public static final UserAuthRequestHostbasedMessagePreparator PREPARATOR =
            new UserAuthRequestHostbasedMessagePreparator();

    public static final UserAuthRequestHostbasedMessageSerializer SERIALIZER =
            new UserAuthRequestHostbasedMessageSerializer();
}
