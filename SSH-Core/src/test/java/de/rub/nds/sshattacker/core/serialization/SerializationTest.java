/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2025 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.serialization;

import static org.junit.jupiter.api.Assertions.*;

import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.sshattacker.core.config.Config;
import de.rub.nds.sshattacker.core.config.ConfigIO;
import de.rub.nds.sshattacker.core.protocol.authentication.AuthenticationPromptEntries;
import de.rub.nds.sshattacker.core.protocol.authentication.AuthenticationResponseEntries;
import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthInfoRequestMessage;
import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthInfoResponseMessage;
import de.rub.nds.sshattacker.core.protocol.authentication.message.holder.AuthenticationPromptEntry;
import de.rub.nds.sshattacker.core.protocol.authentication.message.holder.AuthenticationResponseEntry;
import de.rub.nds.sshattacker.core.workflow.WorkflowTrace;
import de.rub.nds.sshattacker.core.workflow.WorkflowTraceSerializer;
import de.rub.nds.sshattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.sshattacker.core.workflow.action.SendAction;
import java.io.*;
import java.util.ArrayList;
import org.junit.jupiter.api.Test;

public class SerializationTest {

    @Test
    public void testSerializeDeserializeConfig() {
        Config config = new Config();

        ArrayList<AuthenticationResponseEntries> preConfiguredAuthResponses = new ArrayList<>();

        // First Auth Response
        ArrayList<AuthenticationResponseEntry> preConfiguredAuthResponse1 = new ArrayList<>();
        AuthenticationResponseEntry firstResponse = new AuthenticationResponseEntry();
        firstResponse.setResponse(Modifiable.explicit("test"));
        preConfiguredAuthResponse1.add(firstResponse);
        preConfiguredAuthResponses.add(
                new AuthenticationResponseEntries(preConfiguredAuthResponse1));

        // Second Auth Response
        ArrayList<AuthenticationResponseEntry> preConfiguredAuthResponse2 = new ArrayList<>();
        AuthenticationResponseEntry secondResponse = new AuthenticationResponseEntry();
        secondResponse.setResponse(Modifiable.explicit("test2"));
        preConfiguredAuthResponse2.add(secondResponse);
        preConfiguredAuthResponses.add(
                new AuthenticationResponseEntries(preConfiguredAuthResponse2));

        // Auth Prompt
        ArrayList<AuthenticationPromptEntries> preConfiguredAuthPrompts = new ArrayList<>();
        ArrayList<AuthenticationPromptEntry> preConfiguredAuthPrompt1 = new ArrayList<>();
        AuthenticationPromptEntry firstPrompt = new AuthenticationPromptEntry();
        firstPrompt.setPrompt(Modifiable.explicit("AUTHENTICATE:"));
        preConfiguredAuthPrompt1.add(firstPrompt);
        preConfiguredAuthPrompts.add(new AuthenticationPromptEntries(preConfiguredAuthPrompt1));

        config.setPreConfiguredAuthResponses(preConfiguredAuthResponses);
        config.setPreConfiguredAuthPrompts(preConfiguredAuthPrompts);

        ByteArrayOutputStream firstOutputStream = new ByteArrayOutputStream();
        ConfigIO.write(config, firstOutputStream);
        byte[] firstWrite = firstOutputStream.toByteArray();

        Config deserializedConfig = ConfigIO.read(new ByteArrayInputStream(firstWrite));

        ByteArrayOutputStream secondOutputStream = new ByteArrayOutputStream();
        ConfigIO.write(deserializedConfig, secondOutputStream);
        byte[] secondWrite = secondOutputStream.toByteArray();

        assertArrayEquals(firstWrite, secondWrite, "Config serialization should be consitent");
    }

    @Test
    public void testSerializeDeserializeWorkflowTrace() throws Exception {
        WorkflowTrace workflowTrace = new WorkflowTrace();

        // Send Action
        UserAuthInfoRequestMessage request = new UserAuthInfoRequestMessage();
        AuthenticationPromptEntry firstPrompt = new AuthenticationPromptEntry();
        firstPrompt.setPrompt(Modifiable.explicit("AUTHENTICATE:"));
        request.addPromptEntry(firstPrompt);
        workflowTrace.addSshAction(new SendAction(request));

        // Receive Action
        UserAuthInfoResponseMessage response = new UserAuthInfoResponseMessage();
        AuthenticationResponseEntry firstResponse = new AuthenticationResponseEntry();
        firstResponse.setResponse(Modifiable.explicit("test1"));
        response.addResponseEntry(firstResponse);
        workflowTrace.addSshAction(new ReceiveAction(response));

        ByteArrayOutputStream firstOutputStream = new ByteArrayOutputStream();
        WorkflowTraceSerializer.write(firstOutputStream, workflowTrace);
        byte[] firstWrite = firstOutputStream.toByteArray();

        WorkflowTrace deserializedTrace =
                WorkflowTraceSerializer.insecureRead(new ByteArrayInputStream(firstWrite));

        ByteArrayOutputStream secondOutputStream = new ByteArrayOutputStream();
        WorkflowTraceSerializer.write(secondOutputStream, deserializedTrace);
        byte[] secondWrite = secondOutputStream.toByteArray();

        assertArrayEquals(
                firstWrite, secondWrite, "WorkflowTrace serialization should be consitent");
    }
}
