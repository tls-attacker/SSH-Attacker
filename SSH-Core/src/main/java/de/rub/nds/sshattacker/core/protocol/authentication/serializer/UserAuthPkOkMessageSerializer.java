package de.rub.nds.sshattacker.core.protocol.authentication.serializer;

import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthPkOkMessage;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageSerializer;

public class UserAuthPkOkMessageSerializer extends SshMessageSerializer<UserAuthPkOkMessage> {

    public UserAuthPkOkMessageSerializer(UserAuthPkOkMessage message) { super(message); }

    @Override
    public void serializeMessageSpecificContents() { }
}
