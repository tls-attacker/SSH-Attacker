/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.authentication.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.sshattacker.core.constants.AuthenticationMethod;
import de.rub.nds.sshattacker.core.constants.ServiceType;
import de.rub.nds.sshattacker.core.protocol.common.SshMessage;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlSeeAlso;
import java.nio.charset.StandardCharsets;

@XmlAccessorType(XmlAccessType.FIELD)
@XmlSeeAlso({
    UserAuthRequestNoneMessage.class,
    UserAuthRequestPasswordMessage.class,
    UserAuthRequestPublicKeyMessage.class,
    UserAuthRequestHostbasedMessage.class,
    UserAuthRequestKeyboardInteractiveMessage.class
})
public abstract class UserAuthRequestMessage<T extends UserAuthRequestMessage<T>>
        extends SshMessage<T> {

    protected ModifiableInteger userNameLength;
    protected ModifiableString userName;
    protected ModifiableInteger serviceNameLength;
    protected ModifiableString serviceName;
    protected ModifiableInteger methodNameLength;
    protected ModifiableString methodName;

    public ModifiableInteger getUserNameLength() {
        return userNameLength;
    }

    public void setUserNameLength(ModifiableInteger userNameLength) {
        this.userNameLength = userNameLength;
    }

    public void setUserNameLength(int userNameLength) {
        this.userNameLength =
                ModifiableVariableFactory.safelySetValue(this.userNameLength, userNameLength);
    }

    public ModifiableString getUserName() {
        return userName;
    }

    public void setUserName(ModifiableString userName) {
        setUserName(userName, false);
    }

    public void setUserName(String userName) {
        setUserName(userName, false);
    }

    public void setUserName(ModifiableString userName, boolean adjustLengthField) {
        this.userName = userName;
        if (adjustLengthField) {
            setUserNameLength(this.userName.getValue().getBytes(StandardCharsets.UTF_8).length);
        }
    }

    public void setUserName(String userName, boolean adjustLengthField) {
        this.userName = ModifiableVariableFactory.safelySetValue(this.userName, userName);
        if (adjustLengthField) {
            setUserNameLength(this.userName.getValue().getBytes(StandardCharsets.UTF_8).length);
        }
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
        setServiceName(serviceType.toString());
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

    public ModifiableInteger getMethodNameLength() {
        return methodNameLength;
    }

    public void setMethodNameLength(ModifiableInteger methodNameLength) {
        this.methodNameLength = methodNameLength;
    }

    public void setMethodNameLength(int methodNameLength) {
        this.methodNameLength =
                ModifiableVariableFactory.safelySetValue(this.methodNameLength, methodNameLength);
    }

    public ModifiableString getMethodName() {
        return methodName;
    }

    public void setMethodName(ModifiableString methodName) {
        setMethodName(methodName, false);
    }

    public void setMethodName(String methodName) {
        setMethodName(methodName, false);
    }

    public void setMethodName(AuthenticationMethod authenticationMethod) {
        setMethodName(authenticationMethod.toString());
    }

    public void setMethodName(ModifiableString methodName, boolean adjustLengthField) {
        this.methodName = methodName;
        if (adjustLengthField) {
            setMethodNameLength(
                    this.methodName.getValue().getBytes(StandardCharsets.US_ASCII).length);
        }
    }

    public void setMethodName(String methodName, boolean adjustLengthField) {
        this.methodName = ModifiableVariableFactory.safelySetValue(this.methodName, methodName);
        if (adjustLengthField) {
            setMethodNameLength(
                    this.methodName.getValue().getBytes(StandardCharsets.US_ASCII).length);
        }
    }

    public void setMethodName(
            AuthenticationMethod authenticationMethod, boolean adjustLengthField) {
        setMethodName(authenticationMethod.toString(), adjustLengthField);
    }
}
