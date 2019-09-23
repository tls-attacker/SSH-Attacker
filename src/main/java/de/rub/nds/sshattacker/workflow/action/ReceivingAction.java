package de.rub.nds.sshattacker.workflow.action;

import de.rub.nds.sshattacker.protocol.message.BinaryPacket;
import de.rub.nds.sshattacker.protocol.message.Message;
import java.util.List;

public interface ReceivingAction {

    public abstract List<Message> getReceivedMessages();

    public abstract List<BinaryPacket> getReceivedBinaryPackets();
}
