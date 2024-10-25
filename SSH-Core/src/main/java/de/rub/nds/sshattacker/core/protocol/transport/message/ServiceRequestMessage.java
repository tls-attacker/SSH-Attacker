/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.sshattacker.core.constants.ServiceType;
import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.protocol.common.SshMessage;
import de.rub.nds.sshattacker.core.protocol.transport.handler.ServiceRequestMessageHandler;
import de.rub.nds.sshattacker.core.protocol.transport.parser.ServiceRequestMessageParser;
import de.rub.nds.sshattacker.core.protocol.transport.preparator.ServiceRequestMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.transport.serializer.ServiceRequestMessageSerializer;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

public class ServiceRequestMessage extends SshMessage<ServiceRequestMessage> {

    private ModifiableInteger serviceNameLength;
    private ModifiableString serviceName;

    public ModifiableInteger getServiceNameLength() {
        return serviceNameLength;
    }

    public void setServiceNameLength(ModifiableInteger serviceNameLength) {
        this.serviceNameLength = serviceNameLength;
    }

    public void setServiceNameLength(int serviceNameLength) {
        this.serviceNameLength =
                ModifiableVariableFactory.safelySetValue(this.serviceNameLength, serviceNameLength);
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
        this.serviceName = serviceName;
        if (adjustLengthField) {
            setServiceNameLength(
                    this.serviceName.getValue().getBytes(StandardCharsets.US_ASCII).length);
        }
    }

    public void setServiceName(String serviceName, boolean adjustLengthField) {
        this.serviceName = ModifiableVariableFactory.safelySetValue(this.serviceName, serviceName);
        if (adjustLengthField) {
            setServiceNameLength(
                    this.serviceName.getValue().getBytes(StandardCharsets.US_ASCII).length);
        }
    }

    public void setServiceName(ServiceType serviceType, boolean adjustLengthField) {
        setServiceName(serviceType.toString(), adjustLengthField);
    }

    @Override
    public ServiceRequestMessageHandler getHandler(SshContext context) {
        return new ServiceRequestMessageHandler(context);
    }

    @Override
    public ServiceRequestMessageParser getParser(SshContext context, InputStream stream) {
        return new ServiceRequestMessageParser(stream);
    }

    @Override
    public ServiceRequestMessagePreparator getPreparator(SshContext context) {
        return new ServiceRequestMessagePreparator(context.getChooser(), this);
    }

    @Override
    public ServiceRequestMessageSerializer getSerializer(SshContext context) {
        return new ServiceRequestMessageSerializer(this);
    }

    @Override
    public String toShortString() {
        return "SERVICE_REQUEST";
    }
}
