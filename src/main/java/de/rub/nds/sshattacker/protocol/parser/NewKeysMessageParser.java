package de.rub.nds.sshattacker.protocol.parser;

import de.rub.nds.sshattacker.protocol.message.NewKeysMessage;

public class NewKeysMessageParser extends MessageParser<NewKeysMessage> {

    public NewKeysMessageParser(int startPosition, byte[] array) {
        super(startPosition, array);
    }

    public NewKeysMessage createMessage() {
        return new NewKeysMessage();
    }

    protected void parseMessageSpecificPayload(NewKeysMessage msg) {
        // TODO only sets messagetype to NewKeysMessage
    }
}
