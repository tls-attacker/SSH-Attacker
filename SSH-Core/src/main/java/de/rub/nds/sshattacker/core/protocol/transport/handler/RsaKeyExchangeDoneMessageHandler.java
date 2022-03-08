/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.handler;

import de.rub.nds.sshattacker.core.constants.PublicKeyAuthenticationAlgorithm;
import de.rub.nds.sshattacker.core.crypto.hash.ExchangeHash;
import de.rub.nds.sshattacker.core.crypto.signature.JavaSignature;
import de.rub.nds.sshattacker.core.crypto.signature.RawSignature;
import de.rub.nds.sshattacker.core.crypto.signature.SignatureFactory;
import de.rub.nds.sshattacker.core.crypto.signature.SignatureParser;
import de.rub.nds.sshattacker.core.exceptions.AdjustmentException;
import de.rub.nds.sshattacker.core.exceptions.CryptoException;
import de.rub.nds.sshattacker.core.exceptions.NotImplementedException;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageHandler;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageParser;
import de.rub.nds.sshattacker.core.protocol.common.SshMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.transport.message.RsaKeyExchangeDoneMessage;
import de.rub.nds.sshattacker.core.protocol.transport.parser.RsaKeyExchangeDoneMessageParser;
import de.rub.nds.sshattacker.core.state.SshContext;
import java.util.Optional;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class RsaKeyExchangeDoneMessageHandler extends SshMessageHandler<RsaKeyExchangeDoneMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public RsaKeyExchangeDoneMessageHandler(SshContext context) {
        super(context);
    }

    public RsaKeyExchangeDoneMessageHandler(SshContext context, RsaKeyExchangeDoneMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {
        context.setKeyExchangeSignature(message.getSignature().getValue());
        verifySignature();
        setSessionId();
    }

    private void verifySignature() {
        ExchangeHash exchangeHash = context.getExchangeHashInstance();
        Optional<PublicKeyAuthenticationAlgorithm> algorithm = context.getServerHostKeyAlgorithm();
        Optional<byte[]> hostKeyBytes = context.getServerHostKey();

        if (algorithm.isPresent() && hostKeyBytes.isPresent()) {
            RawSignature signature =
                    new SignatureParser(message.getSignature().getValue(), 0).parse();
            JavaSignature javaSignature =
                    SignatureFactory.getVerificationSignatureForHostKey(
                            signature.getSignatureAlgorithm(), hostKeyBytes.get(), algorithm.get());

            try {
                if (javaSignature.verify(exchangeHash.get(), signature.getSignatureBytes())) {
                    LOGGER.debug("Signature verification was successful");
                } else {
                    LOGGER.debug("Signature verification failed: Signature was invalid");
                }
            } catch (CryptoException | NotImplementedException e) {
                // Catch NotImplementedException in case the host key parser is not yet implemented
                LOGGER.debug(
                        "Signature verification failed because an error occurred. "
                                + e.getMessage());
            }
        } else {
            LOGGER.debug(
                    "Signature could not be verified, because host key algorithm or host key bytes are missing");
        }
    }

    private void setSessionId() {
        ExchangeHash exchangeHash = context.getExchangeHashInstance();
        if (context.getSessionID().isEmpty()) {
            try {
                context.setSessionID(exchangeHash.get());
            } catch (AdjustmentException e) {
                raiseAdjustmentException(e);
            }
        }
    }

    @Override
    public SshMessageParser<RsaKeyExchangeDoneMessage> getParser(byte[] array, int startPosition) {
        return new RsaKeyExchangeDoneMessageParser(array, startPosition);
    }

    @Override
    public SshMessagePreparator<RsaKeyExchangeDoneMessage> getPreparator() {
        // TODO: Implement Preparator
        throw new NotImplementedException("RsaKeyExchangeDoneMessage Preparator is missing!");
    }

    @Override
    public SshMessageSerializer<RsaKeyExchangeDoneMessage> getSerializer() {
        // TODO: Implement Serializer
        throw new NotImplementedException("RsaKeyExchangeDoneMessage Serializer is missing!");
    }
}
