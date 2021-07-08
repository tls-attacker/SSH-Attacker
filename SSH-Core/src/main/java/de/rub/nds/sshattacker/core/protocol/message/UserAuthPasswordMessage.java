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
import de.rub.nds.modifiablevariable.singlebyte.ModifiableByte;
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.sshattacker.core.protocol.handler.UserAuthPasswordMessageHandler;
import de.rub.nds.sshattacker.core.protocol.preparator.UserAuthPasswordMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.serializer.UserAuthPasswordMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class UserAuthPasswordMessage extends Message<UserAuthPasswordMessage> {

    private ModifiableString username;
    private ModifiableString servicename;
    private ModifiableByte expectResponse;
    private ModifiableString password;

    public UserAuthPasswordMessage() {
    }

    public ModifiableString getUsername() {
        return username;
    }

    public void setUsername(ModifiableString username) {
        this.username = username;
    }

    public void setUsername(String username) {
        this.username = ModifiableVariableFactory.safelySetValue(this.username, username);
    }

    public ModifiableString getServicename() {
        return servicename;
    }

    public void setServicename(ModifiableString servicename) {
        this.servicename = servicename;
    }

    public void setServicename(String servicename) {
        this.servicename = ModifiableVariableFactory.safelySetValue(this.servicename, servicename);
    }

    public ModifiableByte getExpectResponse() {
        return expectResponse;
    }

    public void setExpectResponse(ModifiableByte expectResponse) {
        this.expectResponse = expectResponse;
    }

    public void setExpectResponse(byte expectResponse) {
        this.expectResponse = ModifiableVariableFactory.safelySetValue(this.expectResponse, expectResponse);
    }

    public ModifiableString getPassword() {
        return password;
    }

    public void setPassword(ModifiableString password) {
        this.password = password;
    }

    public void setPassword(String password) {
        this.password = ModifiableVariableFactory.safelySetValue(this.password, password);
    }

    @Override
    public String toCompactString() {
        return this.getClass().getSimpleName();
    }

    @Override
    public UserAuthPasswordMessageHandler getHandler(SshContext context) {
        return new UserAuthPasswordMessageHandler(context);
    }

    @Override
    public UserAuthPasswordMessageSerializer getSerializer() {
        return new UserAuthPasswordMessageSerializer(this);
    }

    @Override
    public UserAuthPasswordMessagePreparator getPreparator(SshContext context) {
        return new UserAuthPasswordMessagePreparator(context, this);
    }

}
