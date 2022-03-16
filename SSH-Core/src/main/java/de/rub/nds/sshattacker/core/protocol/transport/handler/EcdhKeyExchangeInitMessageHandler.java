/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.handler;

import de.rub.nds.sshattacker.core.constants.KeyExchangeAlgorithm;
import de.rub.nds.sshattacker.core.constants.KeyExchangeFlowType;
import de.rub.nds.sshattacker.core.crypto.hash.EcdhExchangeHash;
import de.rub.nds.sshattacker.core.crypto.hash.ExchangeHash;
import de.rub.nds.sshattacker.core.crypto.kex.DhBasedKeyExchange;
import de.rub.nds.sshattacker.core.crypto.kex.EcdhKeyExchange;
import de.rub.nds.sshattacker.core.crypto.kex.XCurveEcdhKeyExchange;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageHandler;
import de.rub.nds.sshattacker.core.protocol.transport.message.EcdhKeyExchangeInitMessage;
import de.rub.nds.sshattacker.core.protocol.transport.parser.EcdhKeyExchangeInitMessageParser;
import de.rub.nds.sshattacker.core.protocol.transport.preparator.EcdhKeyExchangeInitMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.transport.serializer.EcdhKeyExchangeInitMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;
import java.util.Optional;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class EcdhKeyExchangeInitMessageHandler
        extends SshMessageHandler<EcdhKeyExchangeInitMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public EcdhKeyExchangeInitMessageHandler(SshContext context) {
        super(context);
    }

    public EcdhKeyExchangeInitMessageHandler(
            SshContext context, EcdhKeyExchangeInitMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {
        startFreshKeyExchange();
        updateKeyExchangeWithRemotePublicKey();
        updateExchangeHashWithRemotePublicKey();
    }

    private void startFreshKeyExchange() {
        Optional<KeyExchangeAlgorithm> keyExchangeAlgorithm = context.getKeyExchangeAlgorithm();
        DhBasedKeyExchange keyExchange;
        if (keyExchangeAlgorithm.isPresent()
                && keyExchangeAlgorithm.get().getFlowType() == KeyExchangeFlowType.ECDH) {
            switch (keyExchangeAlgorithm.get()) {
                case CURVE448_SHA512:
                case CURVE25519_SHA256:
                case CURVE25519_SHA256_LIBSSH_ORG:
                    keyExchange = XCurveEcdhKeyExchange.newInstance(keyExchangeAlgorithm.get());
                    break;
                default:
                    keyExchange = EcdhKeyExchange.newInstance(keyExchangeAlgorithm.get());
                    break;
            }
        } else {
            keyExchange =
                    EcdhKeyExchange.newInstance(
                            context.getConfig().getDefaultEcdhKeyExchangeAlgortihm());
        }
        context.setKeyExchangeInstance(keyExchange);
    }

    private void updateKeyExchangeWithRemotePublicKey() {
        DhBasedKeyExchange keyExchange =
                (DhBasedKeyExchange) context.getKeyExchangeInstance().orElseThrow();
        keyExchange.setRemotePublicKey(message.getPublicKey().getValue());
    }

    private void updateExchangeHashWithRemotePublicKey() {
        ExchangeHash exchangeHash = context.getExchangeHashInstance();
        EcdhExchangeHash ecdhExchangeHash;
        if (!(exchangeHash instanceof EcdhExchangeHash)) {
            ecdhExchangeHash = EcdhExchangeHash.from(exchangeHash);
            context.setExchangeHashInstance(ecdhExchangeHash);
        } else {
            ecdhExchangeHash = (EcdhExchangeHash) exchangeHash;
        }
        ecdhExchangeHash.setClientECDHPublicKey(message.getPublicKey().getValue());
    }

    @Override
    public EcdhKeyExchangeInitMessageParser getParser(byte[] array, int startPosition) {
        return new EcdhKeyExchangeInitMessageParser(array, startPosition);
    }

    @Override
    public EcdhKeyExchangeInitMessagePreparator getPreparator() {
        return new EcdhKeyExchangeInitMessagePreparator(context.getChooser(), message);
    }

    @Override
    public EcdhKeyExchangeInitMessageSerializer getSerializer() {
        return new EcdhKeyExchangeInitMessageSerializer(message);
    }
}
