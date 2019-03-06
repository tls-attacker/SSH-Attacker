package de.rub.nds.sshattacker.protocol.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.sshattacker.protocol.handler.Handler;
import de.rub.nds.sshattacker.state.SshContext;

public class NewKeysMessage extends Message {

    public NewKeysMessage() {
        super();
        messageID = ModifiableVariableFactory.safelySetValue(messageID, (byte) 21);
    }

    @Override
    String toCompactString() {
        return "NewKeysMessage";
    }

    @Override
    public Handler getHandler(SshContext context) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

}
