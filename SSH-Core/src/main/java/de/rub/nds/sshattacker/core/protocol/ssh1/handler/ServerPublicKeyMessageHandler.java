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
import de.rub.nds.sshattacker.core.protocol.ssh1.message.ServerPublicKeyMessage;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ServerPublicKeyMessageHandler extends SshMessageHandler<ServerPublicKeyMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ServerPublicKeyMessageHandler(SshContext context) {
        super(context);
    }

    /*public HybridKeyExchangeReplyMessageHandler(
            SshContext context, HybridKeyExchangeReplyMessage message) {
        super(context, message);
    }*/

    @Override
    public void adjustContext(ServerPublicKeyMessage message) {

        String serverKeyModulus =
                new String(
                        message.getServerKey().getPublicKey().getModulus().toByteArray(),
                        StandardCharsets.UTF_8);
        String hostKeyModulus =
                new String(
                        message.getHostKey().getPublicKey().getModulus().toByteArray(),
                        StandardCharsets.UTF_8);
        String cookie =
                new String(message.getAntiSpoofingCookie().getValue(), StandardCharsets.UTF_8);

        String concatenated = serverKeyModulus + hostKeyModulus + cookie;
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            md.update(concatenated.getBytes(StandardCharsets.UTF_8));
            byte[] digest = md.digest();
            sshContext.setSshv1SessionID(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }

        sshContext.setServerKey(message.getServerKey());
        sshContext.setHostKey(message.getHostKey());
        sshContext.setAntiSpoofingCookie(message.getAntiSpoofingCookie().getValue());
        // TODO: Choose correct CipherMethod

        // TODO: Choose correct AuthenticationMethod

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
