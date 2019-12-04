package de.rub.nds.sshattacker.protocol.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.singlebyte.ModifiableByte;
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.protocol.core.message.Serializer;
import de.rub.nds.sshattacker.protocol.handler.Handler;
import de.rub.nds.sshattacker.protocol.handler.UserauthPasswordMessageHandler;
import de.rub.nds.sshattacker.protocol.preparator.Preparator;
import de.rub.nds.sshattacker.protocol.preparator.UserauthPasswordMessagePreparator;
import de.rub.nds.sshattacker.protocol.serializer.UserauthPasswordMessageSerializer;
import de.rub.nds.sshattacker.state.SshContext;

public class UserauthPasswordMessage extends Message {

    private ModifiableString username;
    private ModifiableString servicename;
    private ModifiableByte expectResponse;
    private ModifiableString password;

    public UserauthPasswordMessage() {
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
    public Handler getHandler(SshContext context) {
        return new UserauthPasswordMessageHandler(context);
    }

    @Override
    public Serializer getSerializer() {
        return new UserauthPasswordMessageSerializer(this);
    }

    @Override
    public Preparator getPreparator(SshContext context) {
        return new UserauthPasswordMessagePreparator(context, this);
    }

}
