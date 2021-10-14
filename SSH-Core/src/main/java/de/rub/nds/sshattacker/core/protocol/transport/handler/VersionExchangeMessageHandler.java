/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * <p>Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.handler;

import de.rub.nds.sshattacker.core.protocol.common.*;
import de.rub.nds.sshattacker.core.protocol.transport.message.VersionExchangeMessage;
import de.rub.nds.sshattacker.core.protocol.transport.parser.VersionExchangeMessageParser;
import de.rub.nds.sshattacker.core.protocol.transport.preparator.VersionExchangeMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.transport.serializer.VersionExchangeMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class VersionExchangeMessageHandler extends ProtocolMessageHandler<VersionExchangeMessage> {

    public VersionExchangeMessageHandler(SshContext context) {
        super(context);
    }

    public VersionExchangeMessageHandler(SshContext context, VersionExchangeMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {
        if (context.isClient()) {
            context.setServerVersion(message.getVersion().getValue());
            context.setServerComment(message.getComment().getValue());
            context.getExchangeHashInstance().setServerVersion(message);
        } else {
            context.setClientVersion(message.getVersion().getValue());
            context.setClientComment(message.getComment().getValue());
            context.getExchangeHashInstance().setClientVersion(message);
        }
    }

    @Override
    public VersionExchangeMessageParser getParser(byte[] array, int startPosition) {
        return new VersionExchangeMessageParser(array, startPosition);
    }

    @Override
    public VersionExchangeMessagePreparator getPreparator() {
        return new VersionExchangeMessagePreparator(context, message);
    }

    @Override
    public VersionExchangeMessageSerializer getSerializer() {
        return new VersionExchangeMessageSerializer(message);
    }
}
