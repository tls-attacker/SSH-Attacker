package de.rub.nds.sshattacker.protocol.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.protocol.core.message.Serializer;
import de.rub.nds.sshattacker.constants.MessageIDConstant;
import de.rub.nds.sshattacker.protocol.handler.Handler;
import de.rub.nds.sshattacker.protocol.serializer.ServiceRequestMessageSerializer;
import de.rub.nds.sshattacker.state.SshContext;

public class ServiceRequestMessage extends Message {

    private ModifiableString serviceName;

    public ServiceRequestMessage(){
        messageID = ModifiableVariableFactory.safelySetValue(messageID, MessageIDConstant.SSH_MSG_SERVICE_REQUEST.id);
    }
    
    public ServiceRequestMessage(String serviceName){
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
    public String toCompactString() {
        return this.getClass().getSimpleName(); //test
    }

    @Override
    public Handler getHandler(SshContext context) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public Serializer getSerializer() {
        return new ServiceRequestMessageSerializer(this);
    }

}
