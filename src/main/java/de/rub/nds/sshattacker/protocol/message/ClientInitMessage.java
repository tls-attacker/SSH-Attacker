/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.sshattacker.protocol.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.protocol.core.message.Serializer;
import de.rub.nds.sshattacker.protocol.handler.ClientInitMessageHandler;
import de.rub.nds.sshattacker.protocol.handler.Handler;
import de.rub.nds.sshattacker.protocol.preparator.ClientInitMessagePreparator;
import de.rub.nds.sshattacker.protocol.preparator.Preparator;
import de.rub.nds.sshattacker.protocol.serializer.ClientInitMessageSerializer;
import de.rub.nds.sshattacker.state.SshContext;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement
public class ClientInitMessage extends Message {

    /**
     * version identifier + optional comment
     */
    @ModifiableVariableProperty
    private ModifiableString version;

    @ModifiableVariableProperty
    private ModifiableString comment;

    public ClientInitMessage() {
    }

    public ModifiableString getVersion() {
        return version;
    }

    public void setVersion(ModifiableString version) {
        this.version = version;
    }

    public void setVersion(String version) {
        this.version = ModifiableVariableFactory.safelySetValue(this.version, version);
    }

    public ModifiableString getComment() {
        return comment;
    }

    public void setComment(String comment) {
        this.comment = ModifiableVariableFactory.safelySetValue(this.comment, comment);
    }

    public void setComment(ModifiableString comment) {
        this.comment = comment;
    }

    @Override
    public String toCompactString() {
        return "ClientInitMessage";
    }

    public Handler getHandler(SshContext context) {
        return new ClientInitMessageHandler(context);
    }

    public Serializer getSerializer() {
        return new ClientInitMessageSerializer(this);
    }

    @Override
    public Preparator getPreparator(SshContext context) {
        return new ClientInitMessagePreparator(context, this);
    }
}
