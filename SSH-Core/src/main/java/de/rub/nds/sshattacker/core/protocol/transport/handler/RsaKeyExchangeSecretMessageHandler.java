/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.handler;

import de.rub.nds.sshattacker.core.exceptions.NotImplementedException;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageHandler;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageParser;
import de.rub.nds.sshattacker.core.protocol.common.SshMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.transport.message.RsaKeyExchangeSecretMessage;
import de.rub.nds.sshattacker.core.protocol.transport.preparator.RsaKeyExchangeSecretMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.transport.serializer.RsaKeyExchangeSecretMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class RsaKeyExchangeSecretMessageHandler extends SshMessageHandler<RsaKeyExchangeSecretMessage> {

    public RsaKeyExchangeSecretMessageHandler(SshContext context) {
        super(context);
    }

    public RsaKeyExchangeSecretMessageHandler(SshContext context, RsaKeyExchangeSecretMessage message){
        super(context,message);
    }

    @Override
    public void adjustContext() {
        //TODO: Handle RsaKeyExchangeSecretMessage
    }

    @Override
    public SshMessageParser<RsaKeyExchangeSecretMessage> getParser(byte[] array, int startPosition) {
        //TODO: Implement Parser
        throw new NotImplementedException("RsaKeyExchangeSecretMessage Parser is missing!");
    }

    @Override
    public SshMessagePreparator<RsaKeyExchangeSecretMessage> getPreparator() {
        return new RsaKeyExchangeSecretMessagePreparator(context.getChooser(), message);
    }

    @Override
    public SshMessageSerializer<RsaKeyExchangeSecretMessage> getSerializer() {
        return new RsaKeyExchangeSecretMessageSerializer(message);
    }
}
