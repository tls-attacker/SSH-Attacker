/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.workflow.action;

import de.rub.nds.sshattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.sshattacker.core.protocol.common.ProtocolMessage;
import de.rub.nds.sshattacker.core.protocol.ssh1.general.message.DisconnectMessageSSH1;
import de.rub.nds.sshattacker.core.protocol.ssh1.server.message.FailureMessageSSH1;
import de.rub.nds.sshattacker.core.protocol.ssh1.server.message.SuccessMessageSSH1;
import de.rub.nds.sshattacker.core.protocol.transport.message.RsaKeyExchangeSecretMessage;
import de.rub.nds.sshattacker.core.state.State;
import java.util.ArrayList;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/** Custom Action for dynamically creating and sending {@link RsaKeyExchangeSecretMessage}s */
public class SendBleichenbacherOracleReply extends SendAction {

    private static final Logger LOGGER = LogManager.getLogger();

    /** Creates the action using the default connection alias */
    public SendBleichenbacherOracleReply() {
        this(new byte[0]);
    }

    /**
     * Creates the action using a custom connection alias
     *
     * @param connectionAlias The custom connection alias
     */
    public SendBleichenbacherOracleReply(String connectionAlias) {
        this(new byte[0], connectionAlias);
    }

    /**
     * Creates the action using the default connection alias
     *
     * @param encodedSecret The OAEP encoded shared secret
     */
    public SendBleichenbacherOracleReply(byte[] encodedSecret) {
        super();
    }

    /**
     * Creates the action using a custom connection alias
     *
     * @param encodedSecret The OAEP encoded shared secret
     * @param connectionAlias The custom connection alias
     */
    public SendBleichenbacherOracleReply(byte[] encodedSecret, String connectionAlias) {
        super(connectionAlias);
    }

    @Override
    public void execute(State state) throws WorkflowExecutionException {

        int bbResult = state.getSshContext().getBbResult();
        messages = new ArrayList<>();

        switch (bbResult) {
            case 0:
                LOGGER.debug("nothing is correct, sending Disconnect");
                messages.add(new DisconnectMessageSSH1());

                break;
            case 1:
                LOGGER.debug("first is correct, sending Failure");
                messages.add(new FailureMessageSSH1());
                break;
            case 2:
                LOGGER.debug("first and second is correct, sending success");
                messages.add(new SuccessMessageSSH1());
                break;
        }

        super.execute(state);
    }

    @Override
    public String toString() {
        StringBuilder sb;
        if (isExecuted()) {
            sb = new StringBuilder("Send Bleichenbacher Oracle reply Action:\n");
        } else {
            sb = new StringBuilder("Send Bleichenbacher Oracle replyAction: (not executed)\n");
        }
        sb.append("\tMessages:");
        if (messages != null) {
            for (ProtocolMessage<?> message : messages) {
                sb.append(message.toCompactString());
                sb.append(", ");
            }
            sb.append("\n");
        } else {
            sb.append("null (no messages set)");
        }
        return sb.toString();
    }
}
