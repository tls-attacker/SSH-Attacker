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
import de.rub.nds.sshattacker.core.crypto.kex.DhKeyExchange;
import de.rub.nds.sshattacker.core.exceptions.AdjustmentException;
import de.rub.nds.sshattacker.core.protocol.common.Handler;
import de.rub.nds.sshattacker.core.protocol.layers.CryptoLayerFactory;
import de.rub.nds.sshattacker.core.protocol.transport.message.DhKeyExchangeReplyMessage;
import de.rub.nds.sshattacker.core.state.SshContext;

public class DhKeyExchangeReplyMessageHandler extends Handler<DhKeyExchangeReplyMessage> {

    public DhKeyExchangeReplyMessageHandler(SshContext context) {
        super(context);
    }

    @Override
    public void handle(DhKeyExchangeReplyMessage message) {
        context.setKeyExchangeSignature(message.getSignature().getValue());

        DhKeyExchange dhKeyExchange =
                (DhKeyExchange)
                        context.getKeyExchangeInstance().orElseThrow(AdjustmentException::new);
        dhKeyExchange.setRemotePublicKey(message.getEphemeralPublicKey().getValue());
        dhKeyExchange.computeSharedSecret();

        handleHostKey(message);
        DhNamedExchangeHash dhNamedExchangeHash =
                (DhNamedExchangeHash) context.getExchangeHashInstance();
        dhNamedExchangeHash.setServerDHPublicKey(dhKeyExchange.getRemotePublicKey());
        dhNamedExchangeHash.setSharedSecret(dhKeyExchange.getSharedSecret());
        if (!context.getSessionID().isPresent()) {
            context.setSessionID(dhNamedExchangeHash.get());
        }

        KeyDerivation.deriveKeys(context);
        initializeCryptoLayers();
    }

    private void handleHostKey(DhKeyExchangeReplyMessage message) {
        // TODO: Implement host key types as enumeration
        // TODO: Improve host key handling in separate class
        context.getExchangeHashInstance().setServerHostKey(message.getHostKey().getValue());
    }

    private void initializeCryptoLayers() {
        context.setCryptoLayerClientToServer(CryptoLayerFactory.getCryptoLayer(true, context));
        context.setCryptoLayerServerToClient(CryptoLayerFactory.getCryptoLayer(false, context));
    }
}
