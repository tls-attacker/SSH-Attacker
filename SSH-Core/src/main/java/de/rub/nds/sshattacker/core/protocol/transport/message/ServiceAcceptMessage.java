/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.sshattacker.core.constants.MessageIDConstant;
import de.rub.nds.sshattacker.core.constants.ServiceType;
import de.rub.nds.sshattacker.core.protocol.common.Message;
import de.rub.nds.sshattacker.core.protocol.transport.preparator.ServiceAcceptMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.transport.serializer.ServiceAcceptMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.transport.handler.ServiceAcceptMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;

import java.nio.charset.StandardCharsets;

public class ServiceAcceptMessage extends Message<ServiceAcceptMessage> {

    private ModifiableInteger serviceNameLength;
    private ModifiableString serviceName;

    public ServiceAcceptMessage() {
        super(MessageIDConstant.SSH_MSG_SERVICE_ACCEPT);
    }

    public ModifiableInteger getServiceNameLength() {
        return serviceNameLength;
    }

    public void setServiceNameLength(ModifiableInteger serviceNameLength) {
        this.serviceNameLength = serviceNameLength;
    }

    public void setServiceNameLength(int serviceNameLength) {
        this.serviceNameLength = ModifiableVariableFactory.safelySetValue(this.serviceNameLength, serviceNameLength);
    }

    public ModifiableString getServiceName() {
        return serviceName;
    }

    public void setServiceName(ModifiableString serviceName) {
        setServiceName(serviceName, false);
    }

    public void setServiceName(String serviceName) {
        setServiceName(serviceName, false);
    }

    public void setServiceName(ServiceType serviceType) {
        setServiceName(serviceType.toString(), false);
    }

    public void setServiceName(ModifiableString serviceName, boolean adjustLengthField) {
        if (adjustLengthField) {
            setServiceNameLength(serviceName.getValue().getBytes(StandardCharsets.US_ASCII).length);
        }
        this.serviceName = serviceName;
    }

    public void setServiceName(String serviceName, boolean adjustLengthField) {
        if (adjustLengthField) {
            setServiceNameLength(serviceName.getBytes(StandardCharsets.US_ASCII).length);
        }
        this.serviceName = ModifiableVariableFactory.safelySetValue(this.serviceName, serviceName);
    }

    public void setServiceName(ServiceType serviceType, boolean adjustLengthField) {
        setServiceName(serviceType.toString(), adjustLengthField);
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
