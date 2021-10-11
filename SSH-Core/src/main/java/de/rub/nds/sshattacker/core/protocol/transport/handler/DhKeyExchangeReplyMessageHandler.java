/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * <p>Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.handler;

import de.rub.nds.sshattacker.core.crypto.KeyDerivation;
import de.rub.nds.sshattacker.core.crypto.hash.DhNamedExchangeHash;
import de.rub.nds.sshattacker.core.crypto.hash.ExchangeHash;
import de.rub.nds.sshattacker.core.crypto.kex.DhKeyExchange;
import de.rub.nds.sshattacker.core.crypto.kex.KeyExchange;
import de.rub.nds.sshattacker.core.exceptions.AdjustmentException;
import de.rub.nds.sshattacker.core.protocol.common.Handler;
import de.rub.nds.sshattacker.core.protocol.layers.CryptoLayerFactory;
import de.rub.nds.sshattacker.core.protocol.transport.message.DhKeyExchangeReplyMessage;
import de.rub.nds.sshattacker.core.state.SshContext;
import java.util.Optional;

public class DhKeyExchangeReplyMessageHandler extends Handler<DhKeyExchangeReplyMessage> {

    public DhKeyExchangeReplyMessageHandler(SshContext context) {
        super(context);
    }

    @Override
    public void handle(DhKeyExchangeReplyMessage message) {
        context.setKeyExchangeSignature(message.getSignature().getValue());
        handleHostKey(message);
        updateExchangeHashWithRemotePublicKey(message);
        computeSharedSecret(message);
        updateExchangeHashWithSharedSecret();
        setSessionId();
        KeyDerivation.deriveKeys(context);
        initializeCryptoLayers();
    }

    private void handleHostKey(DhKeyExchangeReplyMessage message) {
        // TODO: Implement host key types as enumeration
        // TODO: Improve host key handling in separate class
        context.getExchangeHashInstance().setServerHostKey(message.getHostKey().getValue());
    }

    private void updateExchangeHashWithRemotePublicKey(DhKeyExchangeReplyMessage message) {
        ExchangeHash exchangeHash = context.getExchangeHashInstance();
        if (exchangeHash instanceof DhNamedExchangeHash) {
            ((DhNamedExchangeHash) exchangeHash)
                    .setServerDHPublicKey(message.getEphemeralPublicKey().getValue());
        } else {
            raiseAdjustmentException(
                    "Exchange hash instance is not an instance of DhNamedExchangeHash, unable to update exchange hash");
        }
    }

    private void computeSharedSecret(DhKeyExchangeReplyMessage message) {
        if (context.getKeyExchangeInstance().isPresent()) {
            KeyExchange keyExchange = context.getKeyExchangeInstance().get();
            if (keyExchange instanceof DhKeyExchange) {
                DhKeyExchange dhKeyExchange = (DhKeyExchange) keyExchange;
                dhKeyExchange.setRemotePublicKey(message.getEphemeralPublicKey().getValue());
                if (dhKeyExchange.getLocalKeyPair() != null) {
                    dhKeyExchange.computeSharedSecret();
                } else {
                    raiseAdjustmentException(
                            "No local key pair is present, unable to compute shared secret");
                }
            } else {
                raiseAdjustmentException(
                        "Key exchange is not an instance of DhKeyExchange, unable to set remote public key and compute shared secret");
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
}
