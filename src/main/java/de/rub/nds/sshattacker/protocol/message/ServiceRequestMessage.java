package de.rub.nds.sshattacker.protocol.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.protocol.core.message.Serializer;
import de.rub.nds.sshattacker.protocol.handler.Handler;
import de.rub.nds.sshattacker.protocol.handler.ServiceRequestMessageHandler;
import de.rub.nds.sshattacker.protocol.preparator.Preparator;
import de.rub.nds.sshattacker.protocol.preparator.ServiceRequestMessagePreparator;
import de.rub.nds.sshattacker.protocol.serializer.ServiceRequestMessageSerializer;
import de.rub.nds.sshattacker.state.SshContext;

public class ServiceRequestMessage extends Message {

    private ModifiableString serviceName;

    public ServiceRequestMessage() {
    }

    public ServiceRequestMessage(String serviceName) {
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
        return this.getClass().getSimpleName(); //test
    }

    @Override
    public Handler getHandler(SshContext context) {
        return new ServiceRequestMessageHandler(context);
    }

    @Override
    public Serializer getSerializer() {
        return new ServiceRequestMessageSerializer(this);
    }

    @Override
    public Preparator getPreparator(SshContext context) {
        return new ServiceRequestMessagePreparator(context, this);
    }

}
