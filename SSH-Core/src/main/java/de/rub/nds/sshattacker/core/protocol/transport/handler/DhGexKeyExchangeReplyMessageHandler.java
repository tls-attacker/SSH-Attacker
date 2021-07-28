/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.handler;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.PublicKeyAuthenticationAlgorithm;
import de.rub.nds.sshattacker.core.crypto.KeyDerivation;
import de.rub.nds.sshattacker.core.crypto.hash.DhGexExchangeHash;
import de.rub.nds.sshattacker.core.crypto.hash.DhGexOldExchangeHash;
import de.rub.nds.sshattacker.core.crypto.hash.ExchangeHash;
import de.rub.nds.sshattacker.core.crypto.kex.DhKeyExchange;
import de.rub.nds.sshattacker.core.exceptions.AdjustmentException;
import de.rub.nds.sshattacker.core.protocol.common.Handler;
import de.rub.nds.sshattacker.core.protocol.layers.CryptoLayerFactory;
import de.rub.nds.sshattacker.core.protocol.transport.message.DhGexKeyExchangeReplyMessage;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.util.Converter;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class DhGexKeyExchangeReplyMessageHandler extends Handler<DhGexKeyExchangeReplyMessage> {

    public DhGexKeyExchangeReplyMessageHandler(SshContext context) {
        super(context);
    }

    @Override
    public void handle(DhGexKeyExchangeReplyMessage message) {
        context.setKeyExchangeSignature(message.getSignature().getValue());

        DhKeyExchange dhKeyExchange = (DhKeyExchange) context.getKeyExchangeInstance().orElseThrow(AdjustmentException::new);
        dhKeyExchange.setRemotePublicKey(message.getEphemeralPublicKey().getValue());
        dhKeyExchange.computeSharedSecret();

        handleHostKey(message);
        ExchangeHash exchangeHash = context.getExchangeHashInstance();
        if(exchangeHash instanceof DhGexExchangeHash) {
            ((DhGexExchangeHash) exchangeHash).setServerDHPublicKey(dhKeyExchange.getRemotePublicKey());
        } else {
            ((DhGexOldExchangeHash) exchangeHash).setServerDHPublicKey(dhKeyExchange.getRemotePublicKey());
        }
        exchangeHash.setSharedSecret(dhKeyExchange.getSharedSecret());
        if(!context.getSessionID().isPresent()) {
            context.setSessionID(exchangeHash.get());
        }

        KeyDerivation.deriveKeys(context);
        initializeCryptoLayers();
    }

    private void handleHostKey(DhGexKeyExchangeReplyMessage message) {
        // TODO: Implement host key types as enumeration
        // TODO: Improve host key handling in separate class
        context.getExchangeHashInstance().setServerHostKey(message.getHostKey().getValue());
    }

    private void initializeCryptoLayers() {
        context.setCryptoLayerClientToServer(CryptoLayerFactory.getCryptoLayer(true, context));
        context.setCryptoLayerServerToClient(CryptoLayerFactory.getCryptoLayer(false, context));
    }
}
