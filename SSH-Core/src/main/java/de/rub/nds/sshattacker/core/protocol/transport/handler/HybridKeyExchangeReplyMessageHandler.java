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
        extends SshMessageHandler<HybridKeyExchangeReplyMessage> implements MessageSentHandler {

    private static final Logger LOGGER = LogManager.getLogger();

    public HybridKeyExchangeReplyMessageHandler(SshContext context) {
        super(context);
    }

    public HybridKeyExchangeReplyMessageHandler(
            SshContext context, HybridKeyExchangeReplyMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {
        KeyExchangeUtil.handleHostKeyMessage(context, message);
        setRemoteValues();
        context.getChooser().getHybridKeyExchange().combineSharedSecrets();
        context.setSharedSecret(context.getChooser().getHybridKeyExchange().getSharedSecret());
        context.getExchangeHashInputHolder()
                .setSharedSecret(context.getChooser().getHybridKeyExchange().getSharedSecret());
        KeyExchangeUtil.computeExchangeHash(context);
        KeyExchangeUtil.handleExchangeHashSignatureMessage(context, message);
        KeyExchangeUtil.setSessionId(context);
        KeyExchangeUtil.generateKeySet(context);
    }

    private void setRemoteValues() {
        byte[] concatenatedHybridKeys = message.getConcatenatedHybridKeys().getValue();

        HybridKeyExchange hybridKeyExchange = context.getChooser().getHybridKeyExchange();
        if (concatenatedHybridKeys.length
                == hybridKeyExchange.getPkAgreementLength()
                        + hybridKeyExchange.getCiphertextLength()) {
            switch (hybridKeyExchange.getCombiner()) {
                case CLASSICAL_CONCATENATE_POSTQUANTUM:
                    byte[] publicKeyClassic =
                            Arrays.copyOfRange(
                                    concatenatedHybridKeys,
                                    0,
                                    hybridKeyExchange.getPkAgreementLength());

                    byte[] combinedKeyShareClassic =
                            Arrays.copyOfRange(
                                    concatenatedHybridKeys,
                                    hybridKeyExchange.getPkAgreementLength(),
                                    concatenatedHybridKeys.length);
                    updateHybridKeys(publicKeyClassic, combinedKeyShareClassic, hybridKeyExchange);
                    break;
                case POSTQUANTUM_CONCATENATE_CLASSICAL:
                    byte[] combinedKeySharePQ =
                            Arrays.copyOfRange(
                                    concatenatedHybridKeys,
                                    0,
                                    hybridKeyExchange.getCiphertextLength());
                    byte[] publicKeyPQ =
                            Arrays.copyOfRange(
                                    concatenatedHybridKeys,
                                    hybridKeyExchange.getCiphertextLength(),
                                    concatenatedHybridKeys.length);

                    updateHybridKeys(publicKeyPQ, combinedKeySharePQ, hybridKeyExchange);

                    break;
                default:
                    LOGGER.warn("Combiner not supported. Can not update message");
                    break;
            }
        } else if (concatenatedHybridKeys.length == hybridKeyExchange.getPkAgreementLength()) {
            hybridKeyExchange.getKeyAgreement().setRemotePublicKey(concatenatedHybridKeys);
        }

        context.getExchangeHashInputHolder().setHybridServerPublicKey(concatenatedHybridKeys);
    }

    private static void updateHybridKeys(
            byte[] remotePublicKey,
            byte[] encryptedSharedSecret,
            HybridKeyExchange hybridKeyExchange) {
        LOGGER.debug(
                "RemoteKey Agreement: {}",
                () -> ArrayConverter.bytesToRawHexString(remotePublicKey));
        hybridKeyExchange.getKeyAgreement().setRemotePublicKey(remotePublicKey);

        LOGGER.debug(
                "Ciphertext Encapsulation: {}",
                () -> ArrayConverter.bytesToRawHexString(encryptedSharedSecret));
        hybridKeyExchange.getKeyEncapsulation().setEncryptedSharedSecret(encryptedSharedSecret);
    }

    @Override
    public void adjustContextAfterMessageSent() {
        context.getExchangeHashInputHolder()
                .setHybridServerPublicKey(message.getConcatenatedHybridKeys().getValue());
    }

    @Override
    public HybridKeyExchangeReplyMessageParser getParser(byte[] array) {
        HybridKeyExchange kex = context.getChooser().getHybridKeyExchange();
        return new HybridKeyExchangeReplyMessageParser(array);
    }

    @Override
    public HybridKeyExchangeReplyMessageParser getParser(byte[] array, int startPosition) {
        HybridKeyExchange kex = context.getChooser().getHybridKeyExchange();
        return new HybridKeyExchangeReplyMessageParser(array, startPosition);
    }

    public static final HybridKeyExchangeReplyMessagePreparator PREPARATOR =
            new HybridKeyExchangeReplyMessagePreparator();

    public static final HybridKeyExchangeReplyMessageSerializer SERIALIZER =
            new HybridKeyExchangeReplyMessageSerializer();
}
