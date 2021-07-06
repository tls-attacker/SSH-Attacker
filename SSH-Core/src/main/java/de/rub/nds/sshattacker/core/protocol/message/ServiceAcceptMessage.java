/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.sshattacker.core.protocol.preparator.ServiceAcceptMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.serializer.ServiceAcceptMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.handler.ServiceAcceptMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;

public class ServiceAcceptMessage extends Message<ServiceAcceptMessage> {

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
    public ServiceAcceptMessageHandler getHandler(SshContext context) {
        return new ServiceAcceptMessageHandler(context);
    }

    @Override
    public ServiceAcceptMessageSerializer getSerializer() {
        return new ServiceAcceptMessageSerializer(this);
    }

    @Override
    public ServiceAcceptMessagePreparator getPreparator(SshContext context) {
        return new ServiceAcceptMessagePreparator(context, this);
    }

}
