/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2024 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.handler;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.crypto.kex.HybridKeyExchange;
import de.rub.nds.sshattacker.core.protocol.common.MessageSentHandler;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageHandler;
import de.rub.nds.sshattacker.core.protocol.transport.message.HybridKeyExchangeInitMessage;
import de.rub.nds.sshattacker.core.protocol.transport.parser.HybridKeyExchangeInitMessageParser;
import de.rub.nds.sshattacker.core.protocol.transport.preparator.HybridKeyExchangeInitMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.transport.serializer.HybridKeyExchangeInitMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;
import java.util.Arrays;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class HybridKeyExchangeInitMessageHandler
        extends SshMessageHandler<HybridKeyExchangeInitMessage> implements MessageSentHandler {

    private static final Logger LOGGER = LogManager.getLogger();

    public HybridKeyExchangeInitMessageHandler(SshContext context) {
        super(context);
    }

    public HybridKeyExchangeInitMessageHandler(
            SshContext context, HybridKeyExchangeInitMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {
        byte[] concatenatedHybridKeys = message.getConcatenatedHybridKeys().getValue();

        HybridKeyExchange hybridKeyExchange = context.getChooser().getHybridKeyExchange();
        switch (hybridKeyExchange.getCombiner()) {
            case CLASSICAL_CONCATENATE_POSTQUANTUM:
                byte[] publicKeyClassic =
                        Arrays.copyOfRange(
                                concatenatedHybridKeys,
                                0,
                                hybridKeyExchange.getPkAgreementLength());
                byte[] encapsulationClassic =
                        Arrays.copyOfRange(
                                concatenatedHybridKeys,
                                hybridKeyExchange.getPkAgreementLength(),
                                concatenatedHybridKeys.length);
                updateHybridKeys(publicKeyClassic, encapsulationClassic, hybridKeyExchange);
                break;
            case POSTQUANTUM_CONCATENATE_CLASSICAL:
                byte[] encapsulationPQ =
                        Arrays.copyOfRange(
                                concatenatedHybridKeys,
                                0,
                                hybridKeyExchange.getPkEncapsulationLength());
                byte[] publicKeyPQ =
                        Arrays.copyOfRange(
                                concatenatedHybridKeys,
                                hybridKeyExchange.getPkEncapsulationLength(),
                                concatenatedHybridKeys.length);
                updateHybridKeys(publicKeyPQ, encapsulationPQ, hybridKeyExchange);
                break;
            default:
                LOGGER.warn("Combiner not supported. Can not update message");
                break;
        }

        context.getExchangeHashInputHolder().setHybridClientPublicKey(concatenatedHybridKeys);
    }

    private static void updateHybridKeys(
            byte[] remotePublicKey, byte[] encapsulationKey, HybridKeyExchange hybridKeyExchange) {
        LOGGER.debug(
                "RemoteKey Agreement: {}",
                () -> ArrayConverter.bytesToRawHexString(remotePublicKey));
        hybridKeyExchange.getKeyAgreement().setRemotePublicKey(remotePublicKey);

        LOGGER.debug(
                "Encapsulation: {}", () -> ArrayConverter.bytesToRawHexString(encapsulationKey));
        hybridKeyExchange.getKeyEncapsulation().setRemotePublicKey(encapsulationKey);
    }

    @Override
    public void adjustContextAfterMessageSent() {
        context.getExchangeHashInputHolder()
                .setHybridClientPublicKey(message.getConcatenatedHybridKeys().getValue());
    }

    @Override
    public HybridKeyExchangeInitMessageParser getParser(byte[] array) {
        HybridKeyExchange kex = context.getChooser().getHybridKeyExchange();
        return new HybridKeyExchangeInitMessageParser(array);
    }

    @Override
    public HybridKeyExchangeInitMessageParser getParser(byte[] array, int startPosition) {
        HybridKeyExchange kex = context.getChooser().getHybridKeyExchange();
        return new HybridKeyExchangeInitMessageParser(array, startPosition);
    }

    public static final HybridKeyExchangeInitMessagePreparator PREPARATOR =
            new HybridKeyExchangeInitMessagePreparator();

    public static final HybridKeyExchangeInitMessageSerializer SERIALIZER =
            new HybridKeyExchangeInitMessageSerializer();
}
