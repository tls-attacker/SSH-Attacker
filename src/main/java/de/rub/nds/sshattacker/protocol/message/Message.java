package de.rub.nds.sshattacker.protocol.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.singlebyte.ModifiableByte;
import de.rub.nds.protocol.core.message.Serializer;
import de.rub.nds.sshattacker.protocol.handler.Handler;
import de.rub.nds.sshattacker.protocol.preparator.Preparator;
import de.rub.nds.sshattacker.state.SshContext;
import javax.xml.bind.annotation.XmlType;

@XmlType(name = "SshMessage")
public abstract class Message extends ProtocolMessage {

    protected ModifiableByte messageID;

    public ModifiableByte getMessageID() {
        return messageID;
    }

    public void setMessageID(ModifiableByte messageID) {
        this.messageID = messageID;
    }

    public void setMessageID(byte messageID) {
        this.messageID = ModifiableVariableFactory.safelySetValue(this.messageID, messageID);
    }

    @Override
    public abstract Handler getHandler(SshContext context);

    public abstract Serializer getSerializer();

    public abstract Preparator getPreparator(SshContext context);

    @Override
    public String toCompactString() {
        return this.getClass().getSimpleName();
    }

}
