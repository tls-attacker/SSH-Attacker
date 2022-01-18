/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.handler;

import de.rub.nds.sshattacker.core.constants.KeyExchangeAlgorithm;
import de.rub.nds.sshattacker.core.crypto.cipher.RsaCipher;
import de.rub.nds.sshattacker.core.crypto.hash.ExchangeHash;
import de.rub.nds.sshattacker.core.crypto.hash.RsaExchangeHash;
import de.rub.nds.sshattacker.core.crypto.kex.RsaKeyExchange;
import de.rub.nds.sshattacker.core.exceptions.AdjustmentException;
import de.rub.nds.sshattacker.core.exceptions.CryptoException;
import de.rub.nds.sshattacker.core.exceptions.NotImplementedException;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageHandler;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageParser;
import de.rub.nds.sshattacker.core.protocol.common.SshMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.transport.message.RsaKeyExchangeDoneMessage;
import de.rub.nds.sshattacker.core.protocol.transport.parser.RsaKeyExchangeDoneMessageParser;
import de.rub.nds.sshattacker.core.state.SshContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class RsaKeyExchangeDoneMessageHandler extends SshMessageHandler<RsaKeyExchangeDoneMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public RsaKeyExchangeDoneMessageHandler(SshContext context) {
        super(context);
    }

    public RsaKeyExchangeDoneMessageHandler(SshContext context, RsaKeyExchangeDoneMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {
        context.setKeyExchangeSignature(message.getSignature().getValue());
        verifyExchangeHash(message);
        setSessionId();
    }

    private void verifyExchangeHash(RsaKeyExchangeDoneMessage message) {
        if (context.getKeyExchangeInstance().isPresent() && context.getKeyExchangeInstance().get() instanceof RsaKeyExchange) {
            RsaKeyExchange keyExchange = (RsaKeyExchange) context.getKeyExchangeInstance().get();

            if (context.getKeyExchangeAlgorithm().isPresent() && context.getExchangeHashInstance() instanceof RsaExchangeHash) {
                KeyExchangeAlgorithm keyExchangeAlgorithm = context.getKeyExchangeAlgorithm().get();

                RsaCipher rsaCipher = new RsaCipher(keyExchangeAlgorithm, keyExchange.getPublicKey());
                boolean signatureIsCorrect;
                try {
                    signatureIsCorrect = rsaCipher.verifySignature(context.getExchangeHashInstance().get(), message.getSignature().getValue());
                } catch (CryptoException e) {
                    LOGGER.error(e);
                    signatureIsCorrect = false;
                }

                if(!signatureIsCorrect) {
                    LOGGER.warn("RSA key exchange failed because of an incorrect signature in the Done message.");
                    //TODO: Abort key exchange
                }
            }
        }
    }

    private void setSessionId() {
        ExchangeHash exchangeHash = context.getExchangeHashInstance();
        if (context.getSessionID().isEmpty()) {
            try {
                context.setSessionID(exchangeHash.get());
            } catch (AdjustmentException e) {
                raiseAdjustmentException(e);
            }
        }
    }

    @Override
    public SshMessageParser<RsaKeyExchangeDoneMessage> getParser(byte[] array, int startPosition) {
        return new RsaKeyExchangeDoneMessageParser(array, startPosition);
    }

    @Override
    public SshMessagePreparator<RsaKeyExchangeDoneMessage> getPreparator() {
        // TODO: Implement Preparator
        throw new NotImplementedException("RsaKeyExchangeDoneMessage Preparator is missing!");
    }

    @Override
    public SshMessageSerializer<RsaKeyExchangeDoneMessage> getSerializer() {
        // TODO: Implement Serializer
        throw new NotImplementedException("RsaKeyExchangeDoneMessage Serializer is missing!");
    }
}
