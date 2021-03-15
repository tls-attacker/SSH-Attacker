package de.rub.nds.sshattacker.protocol.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.protocol.core.message.Serializer;
import de.rub.nds.sshattacker.protocol.handler.Handler;
import de.rub.nds.sshattacker.protocol.handler.UnimplementedMessageHandler;
import de.rub.nds.sshattacker.protocol.preparator.Preparator;
import de.rub.nds.sshattacker.protocol.preparator.UnimplementedMessagePreparator;
import de.rub.nds.sshattacker.protocol.serializer.UnimplementedMessageSerializer;
import de.rub.nds.sshattacker.state.SshContext;

public class UnimplementedMessage extends Message {

    private ModifiableInteger sequenceNumber;

    public ModifiableInteger getSequenceNumber() {
        return sequenceNumber;
    }

    public void setSequenceNumber(ModifiableInteger sequenceNumber) {
        this.sequenceNumber = sequenceNumber;
    }

    public void setSequenceNumber(int sequenceNumber) {
        this.sequenceNumber = ModifiableVariableFactory.safelySetValue(this.sequenceNumber, sequenceNumber);
    }

    @Override
    public Handler getHandler(SshContext context) {
        return new UnimplementedMessageHandler(context);
    }

    @Override
    public Serializer getSerializer() {
        return new UnimplementedMessageSerializer(this);
    }

    @Override
    public Preparator getPreparator(SshContext context) {
        return new UnimplementedMessagePreparator(context, this);
    }
}
