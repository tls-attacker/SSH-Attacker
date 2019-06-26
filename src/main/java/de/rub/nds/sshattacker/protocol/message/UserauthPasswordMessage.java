package de.rub.nds.sshattacker.protocol.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.singlebyte.ModifiableByte;
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.protocol.core.message.Serializer;
import de.rub.nds.sshattacker.constants.MessageIDConstants;
import de.rub.nds.sshattacker.protocol.handler.Handler;
import de.rub.nds.sshattacker.protocol.serializer.UserauthPasswordMessageSerializer;
import de.rub.nds.sshattacker.state.SshContext;

public class UserauthPasswordMessage extends Message{

    private ModifiableString username;
    private ModifiableString servicename;
    private ModifiableByte expectResponse;
    private ModifiableString password;

    public UserauthPasswordMessage(){
        messageID = ModifiableVariableFactory.safelySetValue(messageID, MessageIDConstants.SSH_MSG_USERAUTH_REQUEST);
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
    String toCompactString() {
        return this.getClass().getSimpleName(); // TODO test
    }

    @Override
    public Handler getHandler(SshContext context) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public Serializer getSerializer() {
        return new UserauthPasswordMessageSerializer(this);
    }

}
