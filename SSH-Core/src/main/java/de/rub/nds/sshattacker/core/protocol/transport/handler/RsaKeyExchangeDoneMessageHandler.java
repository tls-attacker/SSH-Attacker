/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.handler;

import de.rub.nds.sshattacker.core.protocol.common.SshMessageHandler;
import de.rub.nds.sshattacker.core.protocol.transport.message.RsaKeyExchangeDoneMessage;
import de.rub.nds.sshattacker.core.protocol.transport.parser.RsaKeyExchangeDoneMessageParser;
import de.rub.nds.sshattacker.core.protocol.transport.preparator.RsaKeyExchangeDoneMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.transport.serializer.RsaKeyExchangeDoneMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.util.KeyExchangeUtil;
import de.rub.nds.sshattacker.core.state.SshContext;

public class RsaKeyExchangeDoneMessageHandler extends SshMessageHandler<RsaKeyExchangeDoneMessage> {

    @Override
    public void adjustContext(SshContext context, RsaKeyExchangeDoneMessage object) {
        KeyExchangeUtil.computeExchangeHash(context);
        KeyExchangeUtil.handleExchangeHashSignatureMessage(context, object);
        KeyExchangeUtil.setSessionId(context);
        KeyExchangeUtil.generateKeySet(context);
    }

    @Override
    public RsaKeyExchangeDoneMessageParser getParser(byte[] array, SshContext context) {
        return new RsaKeyExchangeDoneMessageParser(array);
    }

    @Override
    public RsaKeyExchangeDoneMessageParser getParser(
            byte[] array, int startPosition, SshContext context) {
        return new RsaKeyExchangeDoneMessageParser(array, startPosition);
    }

    public static final RsaKeyExchangeDoneMessagePreparator PREPARATOR =
            new RsaKeyExchangeDoneMessagePreparator();

    public static final RsaKeyExchangeDoneMessageSerializer SERIALIZER =
            new RsaKeyExchangeDoneMessageSerializer();
}
