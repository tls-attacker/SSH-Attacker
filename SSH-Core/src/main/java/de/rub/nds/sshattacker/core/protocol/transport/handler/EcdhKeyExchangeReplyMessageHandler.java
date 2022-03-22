/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.handler;

import de.rub.nds.sshattacker.core.crypto.hash.ExchangeHash;
import de.rub.nds.sshattacker.core.crypto.kex.AbstractEcdhKeyExchange;
import de.rub.nds.sshattacker.core.crypto.kex.KeyExchange;
import de.rub.nds.sshattacker.core.crypto.keys.SshPublicKey;
import de.rub.nds.sshattacker.core.crypto.util.PublicKeyHelper;
import de.rub.nds.sshattacker.core.exceptions.CryptoException;
import de.rub.nds.sshattacker.core.exceptions.MissingExchangeHashInputException;
import de.rub.nds.sshattacker.core.protocol.common.*;
import de.rub.nds.sshattacker.core.protocol.transport.message.EcdhKeyExchangeReplyMessage;
import de.rub.nds.sshattacker.core.protocol.transport.parser.EcdhKeyExchangeReplyMessageParser;
import de.rub.nds.sshattacker.core.protocol.transport.preparator.EcdhKeyExchangeReplyMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.transport.serializer.EcdhKeyExchangeReplyMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;
import java.util.Optional;

public class EcdhKeyExchangeReplyMessageHandler
        extends SshMessageHandler<EcdhKeyExchangeReplyMessage> {

    public EcdhKeyExchangeReplyMessageHandler(SshContext context) {
        super(context);
    }

    public EcdhKeyExchangeReplyMessageHandler(
            SshContext context, EcdhKeyExchangeReplyMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {
        context.setServerExchangeHashSignature(message.getSignature().getValue());
        handleHostKey(message);
        updateExchangeHashWithRemotePublicKey(message);
        computeSharedSecret(message);
        updateExchangeHashWithSharedSecret();
        computeExchangeHash();
        setSessionId();
    }

    private void handleHostKey(EcdhKeyExchangeReplyMessage message) {
        SshPublicKey<?, ?> hostKey =
                PublicKeyHelper.parse(
                        context.getChooser().getServerHostKeyAlgorithm().getKeyFormat(),
                        message.getHostKey().getValue());
        context.setServerHostKey(hostKey);
        context.getExchangeHashInputHolder().setServerHostKey(hostKey);
    }

    private void updateExchangeHashWithRemotePublicKey(EcdhKeyExchangeReplyMessage message) {
        context.getExchangeHashInputHolder()
                .setEcdhServerPublicKey(message.getEphemeralPublicKey().getValue());
    }

    private void computeSharedSecret(EcdhKeyExchangeReplyMessage message) {
        AbstractEcdhKeyExchange keyExchange = context.getChooser().getEcdhKeyExchange();
        keyExchange.setRemotePublicKey(message.getEphemeralPublicKey().getValue());
        if (keyExchange.getLocalKeyPair() != null) {
            keyExchange.computeSharedSecret();
            context.setSharedSecret(keyExchange.getSharedSecret());
        } else {
            LOGGER.warn("No local key pair is present, unable to compute shared secret");
        }
    }

    private void updateExchangeHashWithSharedSecret() {
        KeyExchange keyExchange = context.getChooser().getEcdhKeyExchange();
        if (keyExchange.isComplete()) {
            context.getExchangeHashInputHolder().setSharedSecret(keyExchange.getSharedSecret());
        } else {
            LOGGER.warn(
                    "Key exchange instance is not ready yet, unable to update exchange hash with shared secret");
        }
    }

    private void computeExchangeHash() {
        try {
            context.setExchangeHash(
                    ExchangeHash.computeEcdhHash(
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

    @Override
    public EcdhKeyExchangeReplyMessageParser getParser(byte[] array, int startPosition) {
        return new EcdhKeyExchangeReplyMessageParser(array, startPosition);
    }

    @Override
    public EcdhKeyExchangeReplyMessagePreparator getPreparator() {
        return new EcdhKeyExchangeReplyMessagePreparator(context.getChooser(), message);
    }

    @Override
    public EcdhKeyExchangeReplyMessageSerializer getSerializer() {
        return new EcdhKeyExchangeReplyMessageSerializer(message);
    }
}
