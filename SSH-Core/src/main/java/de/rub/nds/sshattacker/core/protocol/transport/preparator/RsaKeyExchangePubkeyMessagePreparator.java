package de.rub.nds.sshattacker.core.protocol.transport.preparator;

import de.rub.nds.sshattacker.core.constants.MessageIDConstant;
import de.rub.nds.sshattacker.core.protocol.common.SshMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.transport.message.RsaKeyExchangePubkeyMessage;
import de.rub.nds.sshattacker.core.state.SshContext;

public class RsaKeyExchangePubkeyMessagePreparator extends SshMessagePreparator<RsaKeyExchangePubkeyMessage> {

    public RsaKeyExchangePubkeyMessagePreparator(SshContext context, RsaKeyExchangePubkeyMessage message) {
        super(context, message);
    }

    @Override
    public void prepareMessageSpecificContents() {
        getObject().setMessageID(MessageIDConstant.SSH_MSG_KEXRSA_PUBKEY);
        //TODO
    }
}
