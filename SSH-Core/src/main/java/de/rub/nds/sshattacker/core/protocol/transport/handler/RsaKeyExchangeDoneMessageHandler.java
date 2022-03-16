/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.handler;

import de.rub.nds.sshattacker.core.constants.PublicKeyAlgorithm;
import de.rub.nds.sshattacker.core.crypto.hash.ExchangeHash;
import de.rub.nds.sshattacker.core.crypto.signature.*;
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
import java.security.NoSuchAlgorithmException;
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
        Optional<PublicKeyAlgorithm> hostKeyAlgorithm = context.getServerHostKeyAlgorithm();
        Optional<byte[]> hostKeyBytes = context.getServerHostKey();

        if (hostKeyAlgorithm.isPresent() && hostKeyBytes.isPresent()) {
            RawSignature signature =
                    new SignatureParser(message.getSignature().getValue(), 0).parse();
            try {
                VerifyingSignature verifyingSignature =
                        SignatureFactory.getVerifyingSignature(
                                hostKeyAlgorithm.get(), hostKeyBytes.get());
                if (verifyingSignature.verify(exchangeHash.get(), signature.getSignatureBytes())) {
                    LOGGER.info(
                            "Key exchange signature verification successful: Signature is valid.");
                } else {
                    LOGGER.warn(
                            "Key exchange signature verification failed: Signature is invalid - continuing anyway.");
                }
            } catch (NoSuchAlgorithmException e) {
                LOGGER.error(
                        "Key exchange signature verification failed: Unknown or unsupported public key algorithm used.");
                LOGGER.debug(e);
            } catch (CryptoException e) {
                LOGGER.error(
                        "Key exchange signature verification failed: Unexpected cryptographic error - see debug for more details.");
                LOGGER.debug(e);
            }
        } else {
            // TODO: Fallback to Config
            LOGGER.error(
                    "Key exchange signature verification failed: Host key algorithm not negotiated or host key bytes are missing.");
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
