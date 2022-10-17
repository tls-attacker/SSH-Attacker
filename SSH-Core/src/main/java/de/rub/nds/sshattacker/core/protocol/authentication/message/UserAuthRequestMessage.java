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
    UserAuthNoneMessage.class,
    UserAuthPasswordMessage.class,
    UserAuthPubkeyMessage.class,
    UserAuthHostbasedMessage.class,
    UserAuthKeyboardInteractiveMessage.class
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

    public void setMethodName(
            AuthenticationMethod authenticationMethod, boolean adjustLengthField) {
        setMethodName(authenticationMethod.toString(), adjustLengthField);
    }
}
