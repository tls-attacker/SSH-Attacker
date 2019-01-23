package de.rub.nds.sshattacker.protocol.parser;

import de.rub.nds.sshattacker.protocol.message.NewKeysMessage;

public class NewKeysMessageParser extends BinaryPacketParser<NewKeysMessage> {

    public NewKeysMessageParser(int startPosition, byte[] array) {
        super(startPosition, array);
    }

    @Override
    public NewKeysMessage createMessage() {
        return new NewKeysMessage();
    }

    @Override
    protected void parseMessageSpecificPayload(NewKeysMessage msg) {
        
    }

}
