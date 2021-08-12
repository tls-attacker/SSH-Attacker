/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * <p>Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.handler;

import de.rub.nds.sshattacker.core.crypto.KeyDerivation;
import de.rub.nds.sshattacker.core.crypto.hash.DhGexExchangeHash;
import de.rub.nds.sshattacker.core.crypto.hash.DhGexOldExchangeHash;
import de.rub.nds.sshattacker.core.crypto.hash.ExchangeHash;
import de.rub.nds.sshattacker.core.crypto.kex.DhKeyExchange;
import de.rub.nds.sshattacker.core.crypto.kex.KeyExchange;
import de.rub.nds.sshattacker.core.exceptions.AdjustmentException;
import de.rub.nds.sshattacker.core.protocol.common.Handler;
import de.rub.nds.sshattacker.core.protocol.layers.CryptoLayerFactory;
import de.rub.nds.sshattacker.core.protocol.transport.message.DhGexKeyExchangeReplyMessage;
import de.rub.nds.sshattacker.core.state.SshContext;
import java.util.Optional;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class DhGexKeyExchangeReplyMessageHandler extends Handler<DhGexKeyExchangeReplyMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public DhGexKeyExchangeReplyMessageHandler(SshContext context) {
        super(context);
    }

    @Override
    public void handle(DhGexKeyExchangeReplyMessage message) {
        context.setKeyExchangeSignature(message.getSignature().getValue());
        handleHostKey(message);
        updateExchangeHashWithRemotePublicKey(message);
        computeSharedSecret(message);
        updateExchangeHashWithSharedSecret();
        setSessionId();
        KeyDerivation.deriveKeys(context);
        initializeCryptoLayers();
    }

    private void handleHostKey(DhGexKeyExchangeReplyMessage message) {
        // TODO: Implement host key types as enumeration
        // TODO: Improve host key handling in separate class
        context.getExchangeHashInstance().setServerHostKey(message.getHostKey().getValue());
    }

    private void updateExchangeHashWithRemotePublicKey(DhGexKeyExchangeReplyMessage message) {
        ExchangeHash exchangeHash = context.getExchangeHashInstance();
        if (exchangeHash instanceof DhGexExchangeHash) {
            ((DhGexExchangeHash) exchangeHash)
                    .setServerDHPublicKey(message.getEphemeralPublicKey().getValue());
        } else if (exchangeHash instanceof DhGexOldExchangeHash) {
            ((DhGexOldExchangeHash) exchangeHash)
                    .setServerDHPublicKey(message.getEphemeralPublicKey().getValue());
        } else {
            raiseAdjustmentException(
                    "Exchange hash instance is neither DhGexExchangeHash nor DhGexOldExchangeHash, unable to update exchange hash");
        }
    }

    private void computeSharedSecret(DhGexKeyExchangeReplyMessage message) {
        if (context.getKeyExchangeInstance().isPresent()) {
            DhKeyExchange dhKeyExchange = (DhKeyExchange) context.getKeyExchangeInstance().get();
            dhKeyExchange.setRemotePublicKey(message.getEphemeralPublicKey().getValue());
            if (dhKeyExchange.getLocalKeyPair() != null) {
                dhKeyExchange.computeSharedSecret();
            } else {
                raiseAdjustmentException(
                        "No local key pair is present, unable to compute shared secret");
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
