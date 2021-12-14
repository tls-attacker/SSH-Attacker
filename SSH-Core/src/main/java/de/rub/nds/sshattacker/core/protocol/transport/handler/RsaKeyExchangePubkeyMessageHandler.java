/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.handler;

import de.rub.nds.sshattacker.core.constants.KeyExchangeAlgorithm;
import de.rub.nds.sshattacker.core.crypto.hash.ExchangeHash;
import de.rub.nds.sshattacker.core.crypto.hash.RsaExchangeHash;
import de.rub.nds.sshattacker.core.crypto.kex.RsaKeyExchange;
import de.rub.nds.sshattacker.core.exceptions.NotImplementedException;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageHandler;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageParser;
import de.rub.nds.sshattacker.core.protocol.common.SshMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.transport.message.RsaKeyExchangePubkeyMessage;
import de.rub.nds.sshattacker.core.protocol.transport.parser.RsaKeyExchangePubkeyMessageParser;
import de.rub.nds.sshattacker.core.protocol.transport.serializer.RsaKeyExchangePubkeyMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class RsaKeyExchangePubkeyMessageHandler
        extends SshMessageHandler<RsaKeyExchangePubkeyMessage> {

    public RsaKeyExchangePubkeyMessageHandler(SshContext context) {
        super(context);
    }

    public RsaKeyExchangePubkeyMessageHandler(
            SshContext context, RsaKeyExchangePubkeyMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {
        handleHostKey(message);
        createKeyExchangeFromMessage(message);
        RsaExchangeHash rsaExchangeHash = RsaExchangeHash.from(context.getExchangeHashInstance());
        context.setExchangeHashInstance(rsaExchangeHash);
        updateExchangeHashWithTransientPubkey(message);
    }

    private void createKeyExchangeFromMessage(RsaKeyExchangePubkeyMessage message){
        if(context.getKeyExchangeAlgorithm().isPresent()) {

            KeyExchangeAlgorithm keyExchangeAlgorithm = context.getKeyExchangeAlgorithm().get();

            if(keyExchangeAlgorithm.equals(KeyExchangeAlgorithm.RSA1024_SHA1)
                    || keyExchangeAlgorithm.equals(KeyExchangeAlgorithm.RSA2048_SHA256)) {
                RsaKeyExchange rsaKeyExchange = new RsaKeyExchange();
                rsaKeyExchange.setPublicKey(message.getPublicKey());
            } else {
                raiseAdjustmentException("Unable to instantiate a new RSA key exchange, " +
                        "the negotiated key exchange algorithm is: " + keyExchangeAlgorithm);
            }
        } else {
            raiseAdjustmentException("Unable to instantiate a new RSA key exchange, " +
                    "the negotiated key exchange algorithm is not set");
        }
    }

    private void handleHostKey(RsaKeyExchangePubkeyMessage message){
        // TODO: Implement host key types as enumeration
        // TODO: Improve host key handling in separate class
        context.getExchangeHashInstance().setServerHostKey(message.getHostKey().getValue());
    }

    private void updateExchangeHashWithTransientPubkey(RsaKeyExchangePubkeyMessage message){
        ExchangeHash exchangeHash = context.getExchangeHashInstance();
        if (exchangeHash instanceof RsaExchangeHash) {
            ((RsaExchangeHash) exchangeHash).setTransientKey(message.getTransientPubkey().getValue());
        } else {
            raiseAdjustmentException(
                    "Exchange hash instance is not an RsaExchangeHash, unable to update exchange hash");
        }
    }

    @Override
    public SshMessageParser<RsaKeyExchangePubkeyMessage> getParser(
            byte[] array, int startPosition) {
        return new RsaKeyExchangePubkeyMessageParser(array, startPosition);
    }

    @Override
    public SshMessagePreparator<RsaKeyExchangePubkeyMessage> getPreparator() {
        throw new NotImplementedException("RsaKeyExchangePubkeyMessage Preperator is missing!");
        // return new RsaKeyExchangePubkeyMessagePreparator(context.getChooser(), message);
    }

    @Override
    public SshMessageSerializer<RsaKeyExchangePubkeyMessage> getSerializer() {
        // TODO: Implement Serializer
        return new RsaKeyExchangePubkeyMessageSerializer(message);
    }
}
