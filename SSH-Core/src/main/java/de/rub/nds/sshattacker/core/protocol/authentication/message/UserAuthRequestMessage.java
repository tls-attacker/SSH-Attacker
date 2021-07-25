/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.authentication.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.sshattacker.core.constants.AuthenticationMethod;
import de.rub.nds.sshattacker.core.constants.MessageIDConstant;
import de.rub.nds.sshattacker.core.constants.ServiceType;
import de.rub.nds.sshattacker.core.protocol.common.Message;

import java.nio.charset.StandardCharsets;

public abstract class UserAuthRequestMessage<T extends UserAuthRequestMessage<T>> extends Message<T> {

    protected ModifiableInteger userNameLength;
    protected ModifiableString userName;
    protected ModifiableInteger serviceNameLength;
    protected ModifiableString serviceName;
    protected ModifiableInteger methodNameLength;
    protected ModifiableString methodName;

    protected UserAuthRequestMessage(AuthenticationMethod authenticationMethod) {
        super(MessageIDConstant.SSH_MSG_USERAUTH_REQUEST);
        setMethodName(authenticationMethod);
    }

    public ModifiableInteger getUserNameLength() {
        return userNameLength;
    }

    public ModifiableString getUserName() {
        return userName;
    }

    public ModifiableInteger getServiceNameLength() {
        return serviceNameLength;
    }

    public ModifiableString getServiceName() {
        return serviceName;
    }

    public ModifiableInteger getMethodNameLength() {
        return methodNameLength;
    }

    public ModifiableString getMethodName() {
        return methodName;
    }

    public void setUserNameLength(ModifiableInteger userNameLength) {
        this.userNameLength = userNameLength;
    }

    public void setUserNameLength(int userNameLength) {
        this.userNameLength = ModifiableVariableFactory.safelySetValue(this.userNameLength, userNameLength);
    }

    public void setUserName(ModifiableString userName) {
        setUserName(userName, true);
    }

    public void setUserName(String userName) {
        setUserName(userName, true);
    }

    public void setUserName(ModifiableString userName, boolean adjustLengthField) {
        if (adjustLengthField) {
            setUserNameLength(userName.getValue().getBytes(StandardCharsets.UTF_8).length);
        }
        this.userName = userName;
    }

    public void setUserName(String userName, boolean adjustLengthField) {
        if (adjustLengthField) {
            setUserNameLength(userName.getBytes(StandardCharsets.UTF_8).length);
        }
        this.userName = ModifiableVariableFactory.safelySetValue(this.userName, userName);
    }

    public void setServiceNameLength(ModifiableInteger serviceNameLength) {
        this.serviceNameLength = serviceNameLength;
    }

    public void setServiceNameLength(int serviceNameLength) {
        this.serviceNameLength = ModifiableVariableFactory.safelySetValue(this.serviceNameLength, serviceNameLength);
    }

    public void setServiceName(ModifiableString serviceName) {
        setServiceName(serviceName, true);
    }

    public void setServiceName(String serviceName) {
        setServiceName(serviceName, true);
    }

    public void setServiceName(ServiceType serviceType) {
        setServiceName(serviceType.toString());
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

    public void setMethodNameLength(ModifiableInteger methodNameLength) {
        this.methodNameLength = methodNameLength;
    }

    public void setMethodNameLength(int methodNameLength) {
        this.methodNameLength = ModifiableVariableFactory.safelySetValue(this.methodNameLength, methodNameLength);
    }

    public void setMethodName(ModifiableString methodName) {
        setMethodName(methodName, true);
    }

    public void setMethodName(String methodName) {
        setMethodName(methodName, true);
    }

    public void setMethodName(AuthenticationMethod authenticationMethod) {
        setMethodName(authenticationMethod.toString());
    }

    public void setMethodName(ModifiableString methodName, boolean adjustLengthField) {
        if (adjustLengthField) {
            setMethodNameLength(methodName.getValue().getBytes(StandardCharsets.US_ASCII).length);
        }
        this.methodName = methodName;
    }

    public void setMethodName(String methodName, boolean adjustLengthField) {
        if (adjustLengthField) {
            setMethodNameLength(methodName.getBytes(StandardCharsets.US_ASCII).length);
        }
        this.methodName = ModifiableVariableFactory.safelySetValue(this.methodName, methodName);
    }

    public void setMethodName(AuthenticationMethod authenticationMethod, boolean adjustLengthField) {
        setMethodName(authenticationMethod.toString(), adjustLengthField);
    }
}
