package de.rub.nds.sshattacker.protocol.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;

public class NewKeysMessage extends BinaryPacket {

    public NewKeysMessage(){
        super();
        super.messageID = ModifiableVariableFactory.safelySetValue(super.messageID, (byte) 21);
    }
}
