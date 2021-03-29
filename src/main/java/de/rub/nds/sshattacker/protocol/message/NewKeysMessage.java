package de.rub.nds.sshattacker.protocol.message;

import de.rub.nds.sshattacker.protocol.handler.Handler;
import de.rub.nds.sshattacker.protocol.handler.NewKeysMessageHandler;
import de.rub.nds.sshattacker.protocol.preparator.NewKeysMessagePreparator;
import de.rub.nds.sshattacker.protocol.preparator.Preparator;
import de.rub.nds.sshattacker.protocol.serializer.NewKeysMessageSerializer;
import de.rub.nds.sshattacker.protocol.serializer.Serializer;
import de.rub.nds.sshattacker.state.SshContext;

public class NewKeysMessage extends Message {

    public NewKeysMessage() {
        super();
    }

    @Override
    public String toCompactString() {
        return "NewKeysMessage";
    }

    @Override
    public Handler getHandler(SshContext context) {
        return new NewKeysMessageHandler(context);
    }

    @Override
    public Serializer getSerializer() {
        return new NewKeysMessageSerializer(this);
    }

    @Override
    public Preparator getPreparator(SshContext context) {
        return new NewKeysMessagePreparator(context, this);
    }
}
