package de.rub.nds.sshattacker.protocol.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.sshattacker.protocol.handler.Handler;
import de.rub.nds.sshattacker.protocol.handler.IgnoreMessageHandler;
import de.rub.nds.sshattacker.protocol.preparator.IgnoreMessagePreparator;
import de.rub.nds.sshattacker.protocol.preparator.Preparator;
import de.rub.nds.sshattacker.protocol.serializer.IgnoreMessageSerializer;
import de.rub.nds.sshattacker.protocol.serializer.Serializer;
import de.rub.nds.sshattacker.state.SshContext;

public class IgnoreMessage extends Message {

    private ModifiableString data;

    public ModifiableString getData() {
        return data;
    }

    public void setData(ModifiableString data) {
        this.data = data;
    }

    public void setData(String data) {
        this.data = ModifiableVariableFactory.safelySetValue(this.data, data);
    }

    @Override
    public Handler getHandler(SshContext context) {
        return new IgnoreMessageHandler(context);
    }

    @Override
    public Serializer getSerializer() {
        return new IgnoreMessageSerializer(this);
    }

    @Override
    public Preparator getPreparator(SshContext context) {
        return new IgnoreMessagePreparator(context, this);
    }
}
