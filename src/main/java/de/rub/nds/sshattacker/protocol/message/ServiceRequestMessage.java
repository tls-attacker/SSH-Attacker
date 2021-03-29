/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.protocol.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.sshattacker.protocol.handler.ServiceRequestMessageHandler;
import de.rub.nds.sshattacker.protocol.preparator.ServiceRequestMessagePreparator;
import de.rub.nds.sshattacker.protocol.serializer.ServiceRequestMessageSerializer;
import de.rub.nds.sshattacker.state.SshContext;

public class ServiceRequestMessage extends Message<ServiceRequestMessage> {

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
        return this.getClass().getSimpleName(); // test
    }

    @Override
    public ServiceRequestMessageHandler getHandler(SshContext context) {
        return new ServiceRequestMessageHandler(context);
    }

    @Override
    public ServiceRequestMessageSerializer getSerializer() {
        return new ServiceRequestMessageSerializer(this);
    }

    @Override
    public ServiceRequestMessagePreparator getPreparator(SshContext context) {
        return new ServiceRequestMessagePreparator(context, this);
    }

}
