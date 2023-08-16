/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.ssh1.handler;

import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageHandler;
import de.rub.nds.sshattacker.core.protocol.ssh1.message.ClientSessionKeyMessage;
import de.rub.nds.sshattacker.core.protocol.ssh1.message.ServerPublicKeyMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class ClientSessionKeyMessageHandler extends SshMessageHandler<ClientSessionKeyMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ClientSessionKeyMessageHandler(SshContext context) {
        super(context);
    }

    /*public HybridKeyExchangeReplyMessageHandler(
            SshContext context, HybridKeyExchangeReplyMessage message) {
        super(context, message);
    }*/

    @Override
    public void adjustContext(ClientSessionKeyMessage message) {




        // KeyExchangeUtil.handleHostKeyMessage(sshContext, message);
        // setRemoteValues(message);
        /*        sshContext.getChooser().getHybridKeyExchange().combineSharedSecrets();
        sshContext.setSharedSecret(
                sshContext.getChooser().getHybridKeyExchange().getSharedSecret());
        sshContext
                .getExchangeHashInputHolder()
                .setSharedSecret(sshContext.getChooser().getHybridKeyExchange().getSharedSecret());
        KeyExchangeUtil.computeExchangeHash(sshContext);
        */
        /*        KeyExchangeUtil.handleExchangeHashSignatureMessage(sshContext, message);*/
        /*
        KeyExchangeUtil.setSessionId(sshContext);
        KeyExchangeUtil.generateKeySet(sshContext);*/
    }

    /*private void setRemoteValues(ServerPublicKeyMessage message) {
        sshContext
                .getChooser()
                .getHybridKeyExchange()
                .getKeyAgreement()
                .setRemotePublicKey(message.getPublicKey().getValue());
        LOGGER.info(
                "RemoteKey Agreement = "
                        + ArrayConverter.bytesToRawHexString(message.getPublicKey().getValue()));
        sshContext
                .getChooser()
                .getHybridKeyExchange()
                .getKeyEncapsulation()
                .setEncryptedSharedSecret(message.getCombinedKeyShare().getValue());
        LOGGER.info(
                "Ciphertext Encapsulation = "
                        + ArrayConverter.bytesToRawHexString(
                                message.getCombinedKeyShare().getValue()));
        byte[] combined;
        switch (sshContext.getChooser().getHybridKeyExchange().getCombiner()) {
            case CLASSICAL_CONCATENATE_POSTQUANTUM:
                combined =
                        KeyExchangeUtil.concatenateHybridKeys(
                                message.getPublicKey().getValue(),
                                message.getCombinedKeyShare().getValue());
                sshContext.getExchangeHashInputHolder().setHybridServerPublicKey(combined);
                break;
            case POSTQUANTUM_CONCATENATE_CLASSICAL:
                combined =
                        KeyExchangeUtil.concatenateHybridKeys(
                                message.getCombinedKeyShare().getValue(),
                                message.getPublicKey().getValue());
                sshContext.getExchangeHashInputHolder().setHybridServerPublicKey(combined);
                break;
            default:
                LOGGER.warn(
                        "Combiner"
                                + sshContext.getChooser().getHybridKeyExchange().getCombiner()
                                + " is not supported.");
                break;
        }
    }*/

    /*@Override
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
    }*/
}
