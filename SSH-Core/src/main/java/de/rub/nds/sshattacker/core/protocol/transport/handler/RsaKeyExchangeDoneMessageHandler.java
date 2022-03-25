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
import de.rub.nds.sshattacker.core.crypto.keys.SshPublicKey;
import de.rub.nds.sshattacker.core.crypto.signature.*;
import de.rub.nds.sshattacker.core.exceptions.CryptoException;
import de.rub.nds.sshattacker.core.exceptions.MissingExchangeHashInputException;
import de.rub.nds.sshattacker.core.exceptions.NotImplementedException;
import de.rub.nds.sshattacker.core.packet.cipher.keys.KeySet;
import de.rub.nds.sshattacker.core.packet.cipher.keys.KeySetGenerator;
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
        context.setServerExchangeHashSignature(message.getSignature().getValue());
        computeExchangeHash();
        verifySignature();
        setSessionId();
        generateKeySet();
    }

    private void verifySignature() {
        byte[] exchangeHash = context.getExchangeHash().orElse(new byte[0]);
        PublicKeyAlgorithm hostKeyAlgorithm = context.getChooser().getServerHostKeyAlgorithm();
        Optional<SshPublicKey<?, ?>> hostKey = context.getServerHostKey();

        if (hostKey.isPresent()) {
            RawSignature signature =
                    new SignatureParser(message.getSignature().getValue(), 0).parse();
            try {
                VerifyingSignature verifyingSignature =
                        SignatureFactory.getVerifyingSignature(hostKeyAlgorithm, hostKey.get());
                if (verifyingSignature.verify(exchangeHash, signature.getSignatureBytes())) {
                    LOGGER.info(
                            "Key exchange signature verification successful: Signature is valid.");
                } else {
                    LOGGER.warn(
                            "Key exchange signature verification failed: Signature is invalid - continuing anyway.");
                }
            } catch (CryptoException e) {
                LOGGER.error(
                        "Key exchange signature verification failed: Unexpected cryptographic error - see debug for more details.");
                LOGGER.debug(e);
            }
        } else {
            LOGGER.error("Key exchange signature verification failed: Host key missing.");
        }
    }

    private void computeExchangeHash() {
        try {
            context.setExchangeHash(
                    ExchangeHash.computeRsaHash(
                            context.getChooser().getKeyExchangeAlgorithm(),
                            context.getExchangeHashInputHolder()));
        } catch (MissingExchangeHashInputException e) {
            LOGGER.warn(
                    "Failed to compute exchange hash and update context, some inputs for exchange hash computation are missing");
            LOGGER.debug(e);
        } catch (CryptoException e) {
            LOGGER.error(
                    "Unexpected cryptographic exception occurred during exchange hash computation");
            LOGGER.debug(e);
        }
    }

    private void setSessionId() {
        Optional<byte[]> exchangeHash = context.getExchangeHash();
        if (exchangeHash.isPresent()) {
            if (context.getSessionID().isEmpty()) {
                context.setSessionID(exchangeHash.get());
            }
        } else {
            LOGGER.warn("Exchange hash in context is empty, unable to set session id in context");
        }
    }

    private void generateKeySet() {
        KeySet keySet = KeySetGenerator.generateKeySet(context);
        context.setKeySet(keySet);
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
