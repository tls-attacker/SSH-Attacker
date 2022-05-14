package de.rub.nds.sshattacker.core.protocol.authentication.handler;

import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthPkOkMessage;
import de.rub.nds.sshattacker.core.protocol.authentication.parser.UserAuthPkOkMessageParser;
import de.rub.nds.sshattacker.core.protocol.authentication.preparator.UserAuthPkOkMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.authentication.serializer.UserAuthPkOkMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.common.*;
import de.rub.nds.sshattacker.core.state.SshContext;

public class UserAuthPkOkMessageHandler extends SshMessageHandler<UserAuthPkOkMessage> {

    public UserAuthPkOkMessageHandler(SshContext context) { super(context); }

    public UserAuthPkOkMessageHandler(SshContext context, UserAuthPkOkMessage message) { super(context, message); }

    @Override
    public void adjustContext() {
        // TODO compression
    }

    @Override
    public UserAuthPkOkMessageParser getParser(byte[] array) {
        return new UserAuthPkOkMessageParser(array);
    }

    @Override
    public UserAuthPkOkMessageParser getParser(byte[] array, int startPosition) {
        return new UserAuthPkOkMessageParser(array, startPosition);
    }

    @Override
    public UserAuthPkOkMessagePreparator getPreparator() {
        return new UserAuthPkOkMessagePreparator(context.getChooser(), message);
    }

    @Override
    public UserAuthPkOkMessageSerializer getSerializer() {
        return new UserAuthPkOkMessageSerializer(message);
    }
}
