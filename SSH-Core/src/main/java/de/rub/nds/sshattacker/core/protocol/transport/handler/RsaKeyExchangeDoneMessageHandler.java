/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.handler;

import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageHandler;
import de.rub.nds.sshattacker.core.protocol.transport.message.RsaKeyExchangeDoneMessage;
import de.rub.nds.sshattacker.core.protocol.util.KeyExchangeUtil;

public class RsaKeyExchangeDoneMessageHandler extends SshMessageHandler<RsaKeyExchangeDoneMessage> {

    public RsaKeyExchangeDoneMessageHandler(SshContext context) {
        super(context);
    }

    /*public RsaKeyExchangeDoneMessageHandler(SshContext context, RsaKeyExchangeDoneMessage message) {
        super(context, message);
    }*/

    @Override
    public void adjustContext(RsaKeyExchangeDoneMessage message) {
        KeyExchangeUtil.computeExchangeHash(context);
        KeyExchangeUtil.handleExchangeHashSignatureMessage(context, message);
        KeyExchangeUtil.setSessionId(context);
        KeyExchangeUtil.generateKeySet(context);
    }

    /*@Override
    public SshMessageParser<RsaKeyExchangeDoneMessage> getParser(byte[] array) {
        return new RsaKeyExchangeDoneMessageParser(array);
    }

    @Override
    public SshMessageParser<RsaKeyExchangeDoneMessage> getParser(byte[] array, int startPosition) {
        return new RsaKeyExchangeDoneMessageParser(array, startPosition);
    }

    @Override
    public SshMessagePreparator<RsaKeyExchangeDoneMessage> getPreparator() {
        return new RsaKeyExchangeDoneMessagePreparator(context.getChooser(), message);
    }

    @Override
    public SshMessageSerializer<RsaKeyExchangeDoneMessage> getSerializer() {
        return new RsaKeyExchangeDoneMessageSerializer(message);
    }*/
}
