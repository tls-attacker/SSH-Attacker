/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.handler;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.crypto.kex.HybridKeyExchange;
import de.rub.nds.sshattacker.core.protocol.common.MessageSentHandler;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageHandler;
import de.rub.nds.sshattacker.core.protocol.transport.message.HybridKeyExchangeReplyMessage;
import de.rub.nds.sshattacker.core.protocol.transport.parser.HybridKeyExchangeReplyMessageParser;
import de.rub.nds.sshattacker.core.protocol.transport.preparator.HybridKeyExchangeReplyMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.transport.serializer.HybridKeyExchangeReplyMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.util.KeyExchangeUtil;
import de.rub.nds.sshattacker.core.state.SshContext;
import java.util.Arrays;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class HybridKeyExchangeReplyMessageHandler
        extends SshMessageHandler<HybridKeyExchangeReplyMessage>
        implements MessageSentHandler<HybridKeyExchangeReplyMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    @Override
    public void adjustContext(SshContext context, HybridKeyExchangeReplyMessage object) {
        KeyExchangeUtil.handleHostKeyMessage(context, object);
        setRemoteValues(context, object);
        KeyExchangeUtil.computeSharedSecret(context, context.getChooser().getHybridKeyExchange());
        KeyExchangeUtil.computeExchangeHash(context);
        KeyExchangeUtil.handleExchangeHashSignatureMessage(context, object);
        KeyExchangeUtil.setSessionId(context);
        KeyExchangeUtil.generateKeySet(context);
    }

    private static void setRemoteValues(SshContext context, HybridKeyExchangeReplyMessage object) {
        byte[] concatenatedHybridKeys = object.getConcatenatedHybridKeys().getValue();

        HybridKeyExchange hybridKeyExchange = context.getChooser().getHybridKeyExchange();
        if (hybridKeyExchange.getClassicalPublicKeySize()
                        + hybridKeyExchange.getPostQuantumEncapsulationSize()
                != object.getConcatenatedHybridKeysLength().getValue()) {
            LOGGER.warn(
                    "Concatenated Hybrid Keys length does not match the sum of classical public key size and post quantum encapsulation size.");
        }

        if (concatenatedHybridKeys.length
                == hybridKeyExchange.getClassicalPublicKeySize()
                        + hybridKeyExchange.getPostQuantumEncapsulationSize()) {
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
                                    hybridKeyExchange.getPostQuantumEncapsulationSize(),
                                    concatenatedHybridKeys.length),
                            Arrays.copyOfRange(
                                    concatenatedHybridKeys,
                                    0,
                                    hybridKeyExchange.getPostQuantumEncapsulationSize()),
                            hybridKeyExchange);

                    break;
                default:
                    LOGGER.warn("Combiner not supported. Can not update message");
                    break;
            }
        } else if (concatenatedHybridKeys.length == hybridKeyExchange.getClassicalPublicKeySize()) {
            hybridKeyExchange.getClassical().setRemotePublicKey(concatenatedHybridKeys);
        }

        context.getExchangeHashInputHolder().setHybridServerPublicValues(concatenatedHybridKeys);
    }

    private static void updateHybridKeys(
            byte[] classicalPublicKey,
            byte[] postQuantumKeyEncapsulation,
            HybridKeyExchange hybridKeyExchange) {
        LOGGER.debug(
                "RemoteKey Agreement: {}",
                () -> ArrayConverter.bytesToRawHexString(classicalPublicKey));
        hybridKeyExchange.getClassical().setRemotePublicKey(classicalPublicKey);

        LOGGER.debug(
                "Ciphertext Encapsulation: {}",
                () -> ArrayConverter.bytesToRawHexString(postQuantumKeyEncapsulation));
        hybridKeyExchange.getPostQuantum().setEncapsulation(postQuantumKeyEncapsulation);
    }

    @Override
    public void adjustContextAfterMessageSent(
            SshContext context, HybridKeyExchangeReplyMessage object) {
        context.getExchangeHashInputHolder()
                .setHybridServerPublicValues(object.getConcatenatedHybridKeys().getValue());
    }

    @Override
    public HybridKeyExchangeReplyMessageParser getParser(byte[] array, SshContext context) {
        return new HybridKeyExchangeReplyMessageParser(array);
    }

    @Override
    public HybridKeyExchangeReplyMessageParser getParser(
            byte[] array, int startPosition, SshContext context) {
        return new HybridKeyExchangeReplyMessageParser(array, startPosition);
    }

    public static final HybridKeyExchangeReplyMessagePreparator PREPARATOR =
            new HybridKeyExchangeReplyMessagePreparator();

    public static final HybridKeyExchangeReplyMessageSerializer SERIALIZER =
            new HybridKeyExchangeReplyMessageSerializer();
}
