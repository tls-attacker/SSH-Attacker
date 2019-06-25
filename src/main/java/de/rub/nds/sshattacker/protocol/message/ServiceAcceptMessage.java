package de.rub.nds.sshattacker.protocol.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.protocol.core.message.Serializer;
import de.rub.nds.sshattacker.constants.MessageIDConstants;
import de.rub.nds.sshattacker.protocol.handler.Handler;
import de.rub.nds.sshattacker.protocol.serializer.ServiceAcceptMessageSerializer;
import de.rub.nds.sshattacker.state.SshContext;

public class ServiceAcceptMessage extends Message{

    private ModifiableString serviceName;

    public ServiceAcceptMessage(){
        messageID = ModifiableVariableFactory.safelySetValue(this.messageID, MessageIDConstants.SSH_MSG_SERVICE_ACCEPT);
    }
    
    public ServiceAcceptMessage(String serviceName){
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
    String toCompactString() {
        return this.getClass().getSimpleName(); // TODO test?
    }

    @Override
    public Handler getHandler(SshContext context) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public Serializer getSerializer() {
        return new ServiceAcceptMessageSerializer(this);
    }

}
