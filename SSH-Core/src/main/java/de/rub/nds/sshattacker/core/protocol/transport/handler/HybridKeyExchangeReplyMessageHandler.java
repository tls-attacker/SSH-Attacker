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
import de.rub.nds.sshattacker.core.protocol.common.SshMessageHandler;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageParser;
import de.rub.nds.sshattacker.core.protocol.common.SshMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.transport.message.HybridKeyExchangeReplyMessage;
import de.rub.nds.sshattacker.core.protocol.transport.parser.HybridKeyExchangeReplyMessageParser;
import de.rub.nds.sshattacker.core.protocol.transport.preparator.HybridKeyExchangeReplyMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.transport.serializer.HybridKeyExchangeReplyMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.util.KeyExchangeUtil;
import de.rub.nds.sshattacker.core.state.SshContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class HybridKeyExchangeReplyMessageHandler
        extends SshMessageHandler<HybridKeyExchangeReplyMessage> {

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
        KeyExchangeUtil.generateKeySet(context, false);
    }

    private void setRemoteValues() {
        context.getChooser()
                .getHybridKeyExchange()
                .getKeyAgreement()
                .setRemotePublicKey(message.getPublicKey().getValue());
        LOGGER.info(
                "RemoteKey Agreement = "
                        + ArrayConverter.bytesToRawHexString(message.getPublicKey().getValue()));
        context.getChooser()
                .getHybridKeyExchange()
                .getKeyEncapsulation()
                .setEncryptedSharedSecret(message.getCombinedKeyShare().getValue());
        LOGGER.info(
                "Ciphertext Encapsulation = "
                        + ArrayConverter.bytesToRawHexString(
                                message.getCombinedKeyShare().getValue()));
        byte[] combined;
        switch (context.getChooser().getHybridKeyExchange().getCombiner()) {
            case CLASSICAL_CONCATENATE_POSTQUANTUM:
                combined =
                        KeyExchangeUtil.concatenateHybridKeys(
                                message.getPublicKey().getValue(),
                                message.getCombinedKeyShare().getValue());
                context.getExchangeHashInputHolder().setHybridServerPublicKey(combined);
                break;
            case POSTQUANTUM_CONCATENATE_CLASSICAL:
                combined =
                        KeyExchangeUtil.concatenateHybridKeys(
                                message.getCombinedKeyShare().getValue(),
                                message.getPublicKey().getValue());
                context.getExchangeHashInputHolder().setHybridServerPublicKey(combined);
                break;
            default:
                LOGGER.warn(
                        "Combiner"
                                + context.getChooser().getHybridKeyExchange().getCombiner()
                                + " is not supported.");
                break;
        }
    }

    @Override
    public SshMessageParser<HybridKeyExchangeReplyMessage> getParser(byte[] array) {
        HybridKeyExchange kex = context.getChooser().getHybridKeyExchange();
        return new HybridKeyExchangeReplyMessageParser(
                array, kex.getCombiner(), kex.getPkAgreementLength(), kex.getCiphertextLength());
    }

    @Override
    public SshMessageParser<HybridKeyExchangeReplyMessage> getParser(
            byte[] array, int startPosition) {
        HybridKeyExchange kex = context.getChooser().getHybridKeyExchange();
        return new HybridKeyExchangeReplyMessageParser(
                array,
                startPosition,
                kex.getCombiner(),
                kex.getPkAgreementLength(),
                kex.getCiphertextLength());
    }

    @Override
    public SshMessagePreparator<HybridKeyExchangeReplyMessage> getPreparator() {
        HybridKeyExchange kex = context.getChooser().getHybridKeyExchange();
        return new HybridKeyExchangeReplyMessagePreparator(
                context.getChooser(), message, kex.getCombiner());
    }

    @Override
    public SshMessageSerializer<HybridKeyExchangeReplyMessage> getSerializer() {
        HybridKeyExchange kex = context.getChooser().getHybridKeyExchange();
        return new HybridKeyExchangeReplyMessageSerializer(message, kex.getCombiner());
    }
}
