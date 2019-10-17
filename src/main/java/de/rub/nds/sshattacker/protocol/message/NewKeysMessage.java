package de.rub.nds.sshattacker.protocol.message;

import de.rub.nds.protocol.core.message.Serializer;
import de.rub.nds.sshattacker.protocol.handler.Handler;
import de.rub.nds.sshattacker.protocol.preparator.NewKeysMessagePreparator;
import de.rub.nds.sshattacker.protocol.preparator.Preparator;
import de.rub.nds.sshattacker.protocol.serializer.NewKeysMessageSerializer;
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
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
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
