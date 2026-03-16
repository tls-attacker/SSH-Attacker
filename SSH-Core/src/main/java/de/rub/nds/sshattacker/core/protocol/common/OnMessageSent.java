package de.rub.nds.sshattacker.core.protocol.common;

import de.rub.nds.sshattacker.core.state.SshContext;

public interface OnMessageSent {
    void onMessageSent(SshContext context);
}
