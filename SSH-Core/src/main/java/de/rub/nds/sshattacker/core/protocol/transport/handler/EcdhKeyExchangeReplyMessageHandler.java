/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.handler;

import de.rub.nds.sshattacker.core.crypto.KeyDerivation;
import de.rub.nds.sshattacker.core.crypto.hash.EcdhExchangeHash;
import de.rub.nds.sshattacker.core.crypto.hash.ExchangeHash;
import de.rub.nds.sshattacker.core.crypto.kex.EcdhKeyExchange;
import de.rub.nds.sshattacker.core.crypto.kex.KeyExchange;
import de.rub.nds.sshattacker.core.exceptions.AdjustmentException;
import de.rub.nds.sshattacker.core.protocol.common.*;
import de.rub.nds.sshattacker.core.protocol.layers.CryptoLayerFactory;
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
        context.setKeyExchangeSignature(message.getSignature().getValue());
        handleHostKey(message);
        updateExchangeHashWithRemotePublicKey(message);
        computeSharedSecret(message);
        updateExchangeHashWithSharedSecret();
        setSessionId();
        KeyDerivation.deriveKeys(context);
        initializeCryptoLayers();
    }

    private void handleHostKey(EcdhKeyExchangeReplyMessage message) {
        // TODO: Implement host key types as enumeration
        // TODO: Improve host key handling in separate class
        context.getExchangeHashInstance().setServerHostKey(message.getHostKey().getValue());
    }

    private void updateExchangeHashWithRemotePublicKey(EcdhKeyExchangeReplyMessage message) {
        ExchangeHash exchangeHash = context.getExchangeHashInstance();
        if (exchangeHash instanceof EcdhExchangeHash) {
            ((EcdhExchangeHash) exchangeHash)
                    .setServerECDHPublicKey(message.getEphemeralPublicKey().getValue());
        } else {
            raiseAdjustmentException(
                    "Exchange hash instance is not an instance of EcdhExchangeHash, unable to update exchange hash");
        }
    }

    private void computeSharedSecret(EcdhKeyExchangeReplyMessage message) {
        if (context.getKeyExchangeInstance().isPresent()) {
            KeyExchange keyExchange = context.getKeyExchangeInstance().get();
            if (keyExchange instanceof EcdhKeyExchange) {
                EcdhKeyExchange ecdhKeyExchange =
                        (EcdhKeyExchange) context.getKeyExchangeInstance().get();
                ecdhKeyExchange.setRemotePublicKey(message.getEphemeralPublicKey().getValue());
                if (ecdhKeyExchange.getLocalKeyPair() != null) {
                    ecdhKeyExchange.computeSharedSecret();
                } else {
                    raiseAdjustmentException(
                            "No local key pair is present, unable to compute shared secret");
                }
            } else {
                raiseAdjustmentException(
                        "Key exchange is not an instance of EcdhKeyExchange, unable to set remote public key and compute shared secret");
            }
        } else {
            raiseAdjustmentException(
                    "Key exchange instance is not present, unable to set remote public key and compute shared secret");
        }
    }

    private void updateExchangeHashWithSharedSecret() {
        Optional<KeyExchange> keyExchange = context.getKeyExchangeInstance();
        if (keyExchange.isPresent() && keyExchange.get().isComplete()) {
            context.getExchangeHashInstance().setSharedSecret(keyExchange.get().getSharedSecret());
        } else {
            raiseAdjustmentException(
                    "Key exchange instance is either not present or not ready yet, unable to update exchange hash with shared secret");
        }
    }

    private void setSessionId() {
        ExchangeHash exchangeHash = context.getExchangeHashInstance();
        if (!context.getSessionID().isPresent()) {
            try {
                context.setSessionID(exchangeHash.get());
            } catch (AdjustmentException e) {
                raiseAdjustmentException(e);
            }
        }
    }

    private void initializeCryptoLayers() {
        context.setCryptoLayerClientToServer(CryptoLayerFactory.getCryptoLayer(true, context));
        context.setCryptoLayerServerToClient(CryptoLayerFactory.getCryptoLayer(false, context));
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
