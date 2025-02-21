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
        extends SshMessageHandler<HybridKeyExchangeInitMessage>
        implements MessageSentHandler<HybridKeyExchangeInitMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    @Override
    public void adjustContext(SshContext context, HybridKeyExchangeInitMessage object) {
        byte[] concatenatedHybridKeys = object.getConcatenatedHybridKeys().getValue();

        HybridKeyExchange hybridKeyExchange = context.getChooser().getHybridKeyExchange();

        if (hybridKeyExchange.getClassicalPublicKeySize()
                        + hybridKeyExchange.getPostQuantumPublicKeySize()
                != object.getConcatenatedHybridKeysLength().getValue()) {
            LOGGER.warn(
                    "Concatenated Hybrid Keys length does not match the sum of classical and post quantum public key sizes.");
        }

        switch (hybridKeyExchange.getCombiner()) {
            case CLASSICAL_CONCATENATE_POSTQUANTUM:
                updateHybridKeys(
                        Arrays.copyOfRange(
                                concatenatedHybridKeys,
                                0,
                                hybridKeyExchange.getClassicalPublicKeySize()),
                        Arrays.copyOfRange(
                                concatenatedHybridKeys,
                                hybridKeyExchange.getClassicalPublicKeySize(),
                                concatenatedHybridKeys.length),
                        hybridKeyExchange);
                break;
            case POSTQUANTUM_CONCATENATE_CLASSICAL:
                updateHybridKeys(
                        Arrays.copyOfRange(
                                concatenatedHybridKeys,
                                hybridKeyExchange.getPostQuantumPublicKeySize(),
                                concatenatedHybridKeys.length),
                        Arrays.copyOfRange(
                                concatenatedHybridKeys,
                                0,
                                hybridKeyExchange.getPostQuantumPublicKeySize()),
                        hybridKeyExchange);
                break;
            default:
                LOGGER.warn("Combiner not supported. Can not update message");
                break;
        }

        context.getExchangeHashInputHolder().setHybridClientPublicValues(concatenatedHybridKeys);
    }

    private static void updateHybridKeys(
            byte[] classicalPublicKey,
            byte[] postQuantumPublicKey,
            HybridKeyExchange hybridKeyExchange) {
        LOGGER.debug(
                "Classical PK: {}", () -> ArrayConverter.bytesToRawHexString(classicalPublicKey));
        hybridKeyExchange.getClassical().setRemotePublicKey(classicalPublicKey);

        LOGGER.debug(
                "Post Quantum PK: {}",
                () -> ArrayConverter.bytesToRawHexString(postQuantumPublicKey));
        hybridKeyExchange.getPostQuantum().setPublicKey(postQuantumPublicKey);
    }

    @Override
    public void adjustContextAfterMessageSent(
            SshContext context, HybridKeyExchangeInitMessage object) {
        context.getExchangeHashInputHolder()
                .setHybridClientPublicValues(object.getConcatenatedHybridKeys().getValue());
    }

    @Override
    public HybridKeyExchangeInitMessageParser getParser(byte[] array, SshContext context) {
        return new HybridKeyExchangeInitMessageParser(array);
    }

    @Override
    public HybridKeyExchangeInitMessageParser getParser(
            byte[] array, int startPosition, SshContext context) {
        return new HybridKeyExchangeInitMessageParser(array, startPosition);
    }

    public static final HybridKeyExchangeInitMessagePreparator PREPARATOR =
            new HybridKeyExchangeInitMessagePreparator();

    public static final HybridKeyExchangeInitMessageSerializer SERIALIZER =
            new HybridKeyExchangeInitMessageSerializer();
}
