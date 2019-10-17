package de.rub.nds.sshattacker.protocol.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.protocol.core.message.Serializer;
import de.rub.nds.sshattacker.protocol.handler.Handler;
import de.rub.nds.sshattacker.protocol.handler.ServiceAcceptMessageHandler;
import de.rub.nds.sshattacker.protocol.preparator.Preparator;
import de.rub.nds.sshattacker.protocol.serializer.ServiceAcceptMessageSerializer;
import de.rub.nds.sshattacker.state.SshContext;

public class ServiceAcceptMessage extends Message {

    private ModifiableString serviceName;

    public ServiceAcceptMessage() {
    }

    public ServiceAcceptMessage(String serviceName) {
        this();
        this.serviceName = ModifiableVariableFactory.safelySetValue(this.serviceName, serviceName);
    }

    public ModifiableString getServiceName() {
        return serviceName;
    }

    public void setServiceName(ModifiableString serviceName) {
        this.serviceName = serviceName;
    }

    public void setServiceName(String serviceName) {
        this.serviceName = ModifiableVariableFactory.safelySetValue(this.serviceName, serviceName);
    }

    @Override
    public String toCompactString() {
        return this.getClass().getSimpleName();
    }

    @Override
    public Handler getHandler(SshContext context) {
        return new ServiceAcceptMessageHandler(context);
    }

    @Override
    public Serializer getSerializer() {
        return new ServiceAcceptMessageSerializer(this);
    }

    @Override
    public Preparator getPreparator(SshContext context) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

}
