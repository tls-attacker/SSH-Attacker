package de.rub.nds.sshattacker.core.protocol.connection.handler;

import de.rub.nds.sshattacker.core.protocol.common.*;

import de.rub.nds.sshattacker.core.protocol.connection.message.TcpIpForwardRequestMessage;
import de.rub.nds.sshattacker.core.protocol.connection.parser.TcpIpForwardRequestMessageParser;
import de.rub.nds.sshattacker.core.protocol.connection.preparator.TcpIpForwardRequestMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.connection.serializer.TcpIpForwardRequestMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class TcpIpForwardRequestMessageHandler extends SshMessageHandler<TcpIpForwardRequestMessage> {
    
    public TcpIpForwardRequestMessageHandler(SshContext context) {
        super(context);
    }

    public TcpIpForwardRequestMessageHandler(SshContext context, TcpIpForwardRequestMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {
    }

    @Override
    public SshMessageParser<TcpIpForwardRequestMessage> getParser(byte[] array, int startPosition) {
        return new TcpIpForwardRequestMessageParser(array, startPosition);
    }

    @Override
    public SshMessagePreparator<TcpIpForwardRequestMessage> getPreparator() {
        return new TcpIpForwardRequestMessagePreparator(context, message);
    }

    @Override
    public SshMessageSerializer<TcpIpForwardRequestMessage> getSerializer() {
        return new TcpIpForwardRequestMessageSerializer(message);
    }
}
