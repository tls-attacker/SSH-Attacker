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
import de.rub.nds.sshattacker.core.crypto.hash.EcdhExchangeHash;
import de.rub.nds.sshattacker.core.crypto.kex.DhBasedKeyExchange;
import de.rub.nds.sshattacker.core.exceptions.AdjustmentException;
import de.rub.nds.sshattacker.core.protocol.common.Handler;
import de.rub.nds.sshattacker.core.protocol.layers.CryptoLayerFactory;
import de.rub.nds.sshattacker.core.protocol.transport.message.EcdhKeyExchangeReplyMessage;
import de.rub.nds.sshattacker.core.util.Converter;
import de.rub.nds.sshattacker.core.crypto.KeyDerivation;
import de.rub.nds.sshattacker.core.state.SshContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class EcdhKeyExchangeReplyMessageHandler extends Handler<EcdhKeyExchangeReplyMessage> {

    public EcdhKeyExchangeReplyMessageHandler(SshContext context) {
        super(context);
    }

    @Override
    public void handle(EcdhKeyExchangeReplyMessage message) {
        context.setKeyExchangeSignature(message.getSignature().getValue());

        DhBasedKeyExchange keyExchange = (DhBasedKeyExchange) context.getKeyExchangeInstance().orElseThrow(AdjustmentException::new);
        keyExchange.setRemotePublicKey(message.getEphemeralPublicKey().getValue());
        keyExchange.computeSharedSecret();

        handleHostKey(message);
        EcdhExchangeHash ecdhExchangeHash = (EcdhExchangeHash) context.getExchangeHashInstance();
        ecdhExchangeHash.setServerECDHPublicKey(keyExchange.getRemotePublicKey());
        ecdhExchangeHash.setSharedSecret(keyExchange.getSharedSecret());
        if(!context.getSessionID().isPresent()) {
            context.setSessionID(ecdhExchangeHash.get());
        }

        KeyDerivation.deriveKeys(context);

        initializeCryptoLayers();
    }

    private void handleHostKey(EcdhKeyExchangeReplyMessage message) {
        // TODO: Implement host key types as enumeration
        // TODO: Improve host key handling in separate class
        context.getExchangeHashInstance().setServerHostKey(message.getHostKey().getValue());
    }

    private void initializeCryptoLayers() {
        context.setCryptoLayerClientToServer(CryptoLayerFactory.getCryptoLayer(true, context));
        context.setCryptoLayerServerToClient(CryptoLayerFactory.getCryptoLayer(false, context));
    }
}
