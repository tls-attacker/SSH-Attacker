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
import de.rub.nds.sshattacker.core.config.Config;
import de.rub.nds.sshattacker.core.constants.ServiceType;
import de.rub.nds.sshattacker.core.protocol.common.SshMessage;
import de.rub.nds.sshattacker.core.protocol.transport.handler.ServiceAcceptMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import java.nio.charset.StandardCharsets;

public class ServiceAcceptMessage extends SshMessage<ServiceAcceptMessage> {

    private ModifiableInteger serviceNameLength;
    private ModifiableString serviceName;

    public ServiceAcceptMessage() {
        super();
    }

    public ServiceAcceptMessage(ServiceAcceptMessage other) {
        super(other);
        serviceNameLength =
                other.serviceNameLength != null ? other.serviceNameLength.createCopy() : null;
        serviceName = other.serviceName != null ? other.serviceName.createCopy() : null;
    }

    @Override
    public ServiceAcceptMessage createCopy() {
        return new ServiceAcceptMessage(this);
    }

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

    public void setSoftlyServiceName(String serviceName, boolean adjustLengthField, Config config) {
        if (this.serviceName == null || this.serviceName.getOriginalValue() == null) {
            this.serviceName =
                    ModifiableVariableFactory.safelySetValue(this.serviceName, serviceName);
        }
        if (adjustLengthField) {
            if (config.getAlwaysPrepareLengthFields()
                    || serviceNameLength == null
                    || serviceNameLength.getOriginalValue() == null) {
                setServiceNameLength(
                        this.serviceName.getValue().getBytes(StandardCharsets.US_ASCII).length);
            }
        }
    }

    public void setServiceName(ServiceType serviceType, boolean adjustLengthField) {
        setServiceName(serviceType.toString(), adjustLengthField);
    }

    @Override
    public ServiceAcceptMessageHandler getHandler(SshContext context) {
        return new ServiceAcceptMessageHandler(context, this);
    }
}
