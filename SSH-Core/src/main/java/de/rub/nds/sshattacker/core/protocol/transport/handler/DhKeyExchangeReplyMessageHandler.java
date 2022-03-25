/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.handler;

import de.rub.nds.sshattacker.core.crypto.hash.ExchangeHash;
import de.rub.nds.sshattacker.core.crypto.kex.DhKeyExchange;
import de.rub.nds.sshattacker.core.crypto.kex.KeyExchange;
import de.rub.nds.sshattacker.core.crypto.keys.SshPublicKey;
import de.rub.nds.sshattacker.core.crypto.util.PublicKeyHelper;
import de.rub.nds.sshattacker.core.exceptions.CryptoException;
import de.rub.nds.sshattacker.core.exceptions.MissingExchangeHashInputException;
import de.rub.nds.sshattacker.core.packet.cipher.keys.KeySet;
import de.rub.nds.sshattacker.core.packet.cipher.keys.KeySetGenerator;
import de.rub.nds.sshattacker.core.protocol.common.*;
import de.rub.nds.sshattacker.core.protocol.transport.message.DhKeyExchangeReplyMessage;
import de.rub.nds.sshattacker.core.protocol.transport.parser.DhKeyExchangeReplyMessageParser;
import de.rub.nds.sshattacker.core.protocol.transport.preparator.DhKeyExchangeReplyMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.transport.serializer.DhKeyExchangeReplyMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;
import java.util.Optional;

public class DhKeyExchangeReplyMessageHandler extends SshMessageHandler<DhKeyExchangeReplyMessage> {

    public DhKeyExchangeReplyMessageHandler(SshContext context) {
        super(context);
    }

    public DhKeyExchangeReplyMessageHandler(SshContext context, DhKeyExchangeReplyMessage message) {
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
        generateKeySet();
    }

    private void handleHostKey(DhKeyExchangeReplyMessage message) {
        SshPublicKey<?, ?> hostKey =
                PublicKeyHelper.parse(
                        context.getChooser().getServerHostKeyAlgorithm().getKeyFormat(),
                        message.getHostKey().getValue());
        context.setServerHostKey(hostKey);
        context.getExchangeHashInputHolder().setServerHostKey(hostKey);
    }

    private void updateExchangeHashWithRemotePublicKey(DhKeyExchangeReplyMessage message) {
        context.getExchangeHashInputHolder()
                .setDhServerPublicKey(message.getEphemeralPublicKey().getValue());
    }

    private void computeSharedSecret(DhKeyExchangeReplyMessage message) {
        DhKeyExchange keyExchange = context.getChooser().getDhKeyExchange();
        keyExchange.setRemotePublicKey(message.getEphemeralPublicKey().getValue());
        if (keyExchange.getLocalKeyPair() != null) {
            keyExchange.computeSharedSecret();
            context.setSharedSecret(keyExchange.getSharedSecret());
        } else {
            LOGGER.warn("No local key pair is present, unable to compute shared secret");
        }
    }

    private void updateExchangeHashWithSharedSecret() {
        KeyExchange keyExchange = context.getChooser().getDhKeyExchange();
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
                    ExchangeHash.computeDhHash(
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
    public DhKeyExchangeReplyMessageParser getParser(byte[] array, int startPosition) {
        return new DhKeyExchangeReplyMessageParser(array, startPosition);
    }

    @Override
    public SshMessagePreparator<DhKeyExchangeReplyMessage> getPreparator() {
        return new DhKeyExchangeReplyMessagePreparator(context.getChooser(), message);
    }

    @Override
    public SshMessageSerializer<DhKeyExchangeReplyMessage> getSerializer() {
        return new DhKeyExchangeReplyMessageSerializer(message);
    }
}
