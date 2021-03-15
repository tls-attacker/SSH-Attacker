package de.rub.nds.sshattacker.workflow.action;

import de.rub.nds.sshattacker.protocol.message.BinaryPacket;
import de.rub.nds.sshattacker.protocol.message.Message;
import java.util.List;

public interface SendingAction {

    public abstract List<Message> getSendMessages();

    public abstract List<BinaryPacket> getSendBinaryPackets();
}
