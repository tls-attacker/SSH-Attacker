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
import de.rub.nds.sshattacker.core.protocol.transport.message.DhGexKeyExchangeReplyMessage;
import de.rub.nds.sshattacker.core.protocol.transport.parser.DhGexKeyExchangeReplyMessageParser;
import de.rub.nds.sshattacker.core.protocol.transport.preparator.DhGexKeyExchangeReplyMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.transport.serializer.DhGexKeyExchangeReplyMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;
import java.util.Optional;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class DhGexKeyExchangeReplyMessageHandler
        extends SshMessageHandler<DhGexKeyExchangeReplyMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public DhGexKeyExchangeReplyMessageHandler(SshContext context) {
        super(context);
    }

    public DhGexKeyExchangeReplyMessageHandler(
            SshContext context, DhGexKeyExchangeReplyMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {
        context.setServerExchangeHashSignature(message.getSignature().getValue());
        handleHostKey();
        updateExchangeHashWithRemotePublicKey();
        computeSharedSecret();
        updateExchangeHashWithSharedSecret();
        computeExchangeHash();
        setSessionId();
        generateKeySet();
    }

    private void handleHostKey() {
        SshPublicKey<?, ?> hostKey =
                PublicKeyHelper.parse(
                        context.getChooser().getServerHostKeyAlgorithm().getKeyFormat(),
                        message.getHostKey().getValue());
        context.setServerHostKey(hostKey);
        context.getExchangeHashInputHolder().setServerHostKey(hostKey);
    }

    private void updateExchangeHashWithRemotePublicKey() {
        context.getExchangeHashInputHolder()
                .setDhGexServerPublicKey(message.getEphemeralPublicKey().getValue());
    }

    private void computeSharedSecret() {
        DhKeyExchange keyExchange = context.getChooser().getDhGexKeyExchange();
        keyExchange.setRemotePublicKey(message.getEphemeralPublicKey().getValue());
        if (keyExchange.getLocalKeyPair() != null) {
            keyExchange.computeSharedSecret();
            context.setSharedSecret(keyExchange.getSharedSecret());
        } else {
            LOGGER.warn("No local key pair is present, unable to compute shared secret");
        }
    }

    private void updateExchangeHashWithSharedSecret() {
        KeyExchange keyExchange = context.getChooser().getDhGexKeyExchange();
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
                    ExchangeHash.computeDhGexHash(
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
    public DhGexKeyExchangeReplyMessageParser getParser(byte[] array, int startPosition) {
        return new DhGexKeyExchangeReplyMessageParser(array, startPosition);
    }

    @Override
    public DhGexKeyExchangeReplyMessagePreparator getPreparator() {
        return new DhGexKeyExchangeReplyMessagePreparator(context.getChooser(), message);
    }

    @Override
    public DhGexKeyExchangeReplyMessageSerializer getSerializer() {
        return new DhGexKeyExchangeReplyMessageSerializer(message);
    }
}
