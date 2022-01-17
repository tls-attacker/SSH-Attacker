/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.handler;

import de.rub.nds.sshattacker.core.crypto.hash.ExchangeHash;
import de.rub.nds.sshattacker.core.exceptions.AdjustmentException;
import de.rub.nds.sshattacker.core.exceptions.NotImplementedException;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageHandler;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageParser;
import de.rub.nds.sshattacker.core.protocol.common.SshMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.transport.message.RsaKeyExchangeDoneMessage;
import de.rub.nds.sshattacker.core.protocol.transport.parser.RsaKeyExchangeDoneMessageParser;
import de.rub.nds.sshattacker.core.state.SshContext;

public class RsaKeyExchangeDoneMessageHandler extends SshMessageHandler<RsaKeyExchangeDoneMessage> {

    public RsaKeyExchangeDoneMessageHandler(SshContext context) {
        super(context);
    }

    public RsaKeyExchangeDoneMessageHandler(SshContext context, RsaKeyExchangeDoneMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {
        context.setKeyExchangeSignature(message.getSignature().getValue());
        //TODO: validate signature
        setSessionId();
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
