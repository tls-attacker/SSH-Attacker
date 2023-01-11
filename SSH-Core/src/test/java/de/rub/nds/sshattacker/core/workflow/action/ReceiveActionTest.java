/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.workflow.action;

import static de.rub.nds.sshattacker.core.workflow.action.ReceiveAction.ReceiveOption;

import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthNoneMessage;
import de.rub.nds.sshattacker.core.protocol.connection.message.GlobalRequestOpenSshHostKeysMessage;
import de.rub.nds.sshattacker.core.protocol.transport.message.AsciiMessage;
import de.rub.nds.sshattacker.core.protocol.transport.message.DebugMessage;
import de.rub.nds.sshattacker.core.protocol.transport.message.IgnoreMessage;
import de.rub.nds.sshattacker.core.protocol.transport.message.KeyExchangeInitMessage;
import de.rub.nds.sshattacker.core.protocol.transport.message.VersionExchangeMessage;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class ReceiveActionTest {

    @Test
    public void testGetReceiveOptionsEmptyByDefault() {
        final ReceiveAction action = new ReceiveAction();
        Assertions.assertTrue(action.getReceiveOptions().isEmpty());
    }

    @Test
    public void testSetAndGetReceiveOptions() {
        final ReceiveAction action = new ReceiveAction();
        final Set<ReceiveOption> options =
                Set.of(ReceiveOption.CHECK_ONLY_EXPECTED, ReceiveOption.EARLY_CLEAN_SHUTDOWN);
        action.setReceiveOptions(options);
        Assertions.assertEquals(options, action.getReceiveOptions());
    }

    @Test
    public void testExecutedAsPlannedIsTrueWithNoExpectedMessagesAndNoReceivedMessages() {
        final ReceiveAction action = new ReceiveAction();
        action.setExpectedMessages(List.of());
        action.setReceivedMessages(List.of());
        Assertions.assertTrue(action.executedAsPlanned());
    }

    @Test
    public void testExecutedAsPlannedIsTrueWithNoExpectedMessagesAndSomeReceivedMessages() {
        final ReceiveAction action = new ReceiveAction();
        action.setExpectedMessages(List.of());
        action.setReceivedMessages(
                List.of(new VersionExchangeMessage(), new KeyExchangeInitMessage()));
        Assertions.assertTrue(action.executedAsPlanned());
    }

    @Test
    public void testExecutedAsPlannedIsTrueWithExactMatch() {
        final ReceiveAction action = new ReceiveAction();
        action.setExpectedMessages(
                List.of(new VersionExchangeMessage(), new KeyExchangeInitMessage()));
        action.setReceivedMessages(
                List.of(new VersionExchangeMessage(), new KeyExchangeInitMessage()));
        Assertions.assertTrue(action.executedAsPlanned());
    }

    @Test
    public void testExecutedAsPlannedIsFalseWithLessReceivedMessages() {
        final ReceiveAction action = new ReceiveAction();
        action.setExpectedMessages(
                List.of(new VersionExchangeMessage(), new KeyExchangeInitMessage()));
        action.setReceivedMessages(List.of(new VersionExchangeMessage()));
        Assertions.assertFalse(action.executedAsPlanned());
    }

    @Test
    public void testExecutedAsPlannedIsFalseWithDifferentReceivedMessages() {
        final ReceiveAction action = new ReceiveAction();
        action.setExpectedMessages(
                List.of(new VersionExchangeMessage(), new KeyExchangeInitMessage()));
        action.setReceivedMessages(List.of(new VersionExchangeMessage(), new AsciiMessage()));
        Assertions.assertFalse(action.executedAsPlanned());
    }

    @Test
    public void testExecutedAsPlannedIsFalseWithDifferentOrder() {
        final ReceiveAction action = new ReceiveAction();
        action.setExpectedMessages(
                List.of(new VersionExchangeMessage(), new KeyExchangeInitMessage()));
        action.setReceivedMessages(
                List.of(new KeyExchangeInitMessage(), new VersionExchangeMessage()));
        Assertions.assertFalse(action.executedAsPlanned());
    }

    @Test
    public void testExecutedAsPlannedIsTrueWithUnexpectedIgnoreMessagesAndDefaultReceiveOptions() {
        final ReceiveAction action = new ReceiveAction();
        action.setExpectedMessages(
                List.of(new VersionExchangeMessage(), new KeyExchangeInitMessage()));
        action.setReceivedMessages(
                List.of(
                        new IgnoreMessage(),
                        new VersionExchangeMessage(),
                        new IgnoreMessage(),
                        new IgnoreMessage(),
                        new KeyExchangeInitMessage()));
        Assertions.assertTrue(action.executedAsPlanned());
    }

    @Test
    public void
            testExecutedAsPlannedIsFalseWithUnexpectedIgnoreMessagesAndFailOnUnexpectedIgnoreMessagesEnabled() {
        final ReceiveAction action =
                new ReceiveAction(ReceiveOption.FAIL_ON_UNEXPECTED_IGNORE_MESSAGES);
        action.setExpectedMessages(
                List.of(new VersionExchangeMessage(), new KeyExchangeInitMessage()));
        action.setReceivedMessages(
                List.of(
                        new IgnoreMessage(),
                        new VersionExchangeMessage(),
                        new IgnoreMessage(),
                        new IgnoreMessage(),
                        new KeyExchangeInitMessage()));
        Assertions.assertFalse(action.executedAsPlanned());
    }

    @Test
    public void testExecutedAsPlannedIsTrueWithUnexpectedDebugMessagesAndDefaultReceiveOptions() {
        final ReceiveAction action = new ReceiveAction();
        action.setExpectedMessages(
                List.of(new VersionExchangeMessage(), new KeyExchangeInitMessage()));
        action.setReceivedMessages(
                List.of(
                        new DebugMessage(),
                        new VersionExchangeMessage(),
                        new DebugMessage(),
                        new DebugMessage(),
                        new KeyExchangeInitMessage()));
        Assertions.assertTrue(action.executedAsPlanned());
    }

    @Test
    public void
            testExecutedAsPlannedIsFalseWithUnexpectedDebugMessagesAndFailOnUnexpectedDebugMessagesEnabled() {
        final ReceiveAction action =
                new ReceiveAction(ReceiveOption.FAIL_ON_UNEXPECTED_DEBUG_MESSAGES);
        action.setExpectedMessages(
                List.of(new VersionExchangeMessage(), new KeyExchangeInitMessage()));
        action.setReceivedMessages(
                List.of(
                        new DebugMessage(),
                        new VersionExchangeMessage(),
                        new DebugMessage(),
                        new DebugMessage(),
                        new KeyExchangeInitMessage()));
        Assertions.assertFalse(action.executedAsPlanned());
    }

    @Test
    public void testExecutedAsPlannedIsTrueWithExpectedIgnoreMessagesAndDefaultReceiveOptions() {
        final ReceiveAction action = new ReceiveAction();
        action.setExpectedMessages(
                List.of(
                        new VersionExchangeMessage(),
                        new IgnoreMessage(),
                        new KeyExchangeInitMessage()));
        action.setReceivedMessages(
                List.of(
                        new VersionExchangeMessage(),
                        new IgnoreMessage(),
                        new KeyExchangeInitMessage()));
        Assertions.assertTrue(action.executedAsPlanned());
    }

    @Test
    public void
            testExecutedAsPlannedIsTrueWithExpectedIgnoreMessagesAndFailOnUnexpectedIgnoreMessagesEnabled() {
        final ReceiveAction action =
                new ReceiveAction(ReceiveOption.FAIL_ON_UNEXPECTED_IGNORE_MESSAGES);
        action.setExpectedMessages(
                List.of(
                        new VersionExchangeMessage(),
                        new IgnoreMessage(),
                        new KeyExchangeInitMessage()));
        action.setReceivedMessages(
                List.of(
                        new VersionExchangeMessage(),
                        new IgnoreMessage(),
                        new KeyExchangeInitMessage()));
        Assertions.assertTrue(action.executedAsPlanned());
    }

    @Test
    public void
            testExecutedAsPlannedIsTrueWithExpectedAndUnexpectedIgnoreMessagesAndDefaultReceiveOptions() {
        final ReceiveAction action = new ReceiveAction();
        action.setExpectedMessages(
                List.of(
                        new VersionExchangeMessage(),
                        new IgnoreMessage(),
                        new KeyExchangeInitMessage()));
        action.setReceivedMessages(
                List.of(
                        new IgnoreMessage(),
                        new VersionExchangeMessage(),
                        new IgnoreMessage(),
                        new IgnoreMessage(),
                        new KeyExchangeInitMessage()));
        Assertions.assertTrue(action.executedAsPlanned());
    }

    @Test
    public void testExecutedAsPlannedIsFalseWithUnexpectedMessagesAndDefaultReceiveOptions() {
        final ReceiveAction action = new ReceiveAction();
        action.setExpectedMessages(
                List.of(new VersionExchangeMessage(), new KeyExchangeInitMessage()));
        action.setReceivedMessages(
                List.of(
                        new AsciiMessage(),
                        new VersionExchangeMessage(),
                        new IgnoreMessage(),
                        new UserAuthNoneMessage(),
                        new KeyExchangeInitMessage()));
        Assertions.assertFalse(action.executedAsPlanned());
    }

    @Test
    public void testExecutedAsPlannedIsTrueWithUnexpectedMessagesAndCheckOnlyExpectedEnabled() {
        final ReceiveAction action = new ReceiveAction(ReceiveOption.CHECK_ONLY_EXPECTED);
        action.setExpectedMessages(
                List.of(new VersionExchangeMessage(), new KeyExchangeInitMessage()));
        action.setReceivedMessages(
                List.of(
                        new AsciiMessage(),
                        new VersionExchangeMessage(),
                        new IgnoreMessage(),
                        new UserAuthNoneMessage(),
                        new KeyExchangeInitMessage()));
        Assertions.assertTrue(action.executedAsPlanned());
    }

    @Test
    public void
            testExecutedAsPlannedIsFalseWithUnexpectedGlobalRequestMessagesAndDefaultReceiveOptions() {
        final ReceiveAction action = new ReceiveAction();
        action.setExpectedMessages(
                List.of(new VersionExchangeMessage(), new KeyExchangeInitMessage()));
        action.setReceivedMessages(
                List.of(
                        new VersionExchangeMessage(),
                        Optional.of(new GlobalRequestOpenSshHostKeysMessage())
                                .map(
                                        message -> {
                                            message.setWantReply((byte) 0);
                                            return message;
                                        })
                                .get(),
                        new KeyExchangeInitMessage()));
        Assertions.assertFalse(action.executedAsPlanned());
    }

    @Test
    public void
            testExecutedAsPlannedIsTrueWithUnexpectedGlobalRequestMessagesWithoutWantReplyAndIgnoreUnexpectedGlobalRequestsWithoutWantReplyEnabled() {
        final ReceiveAction action =
                new ReceiveAction(
                        ReceiveOption.IGNORE_UNEXPECTED_GLOBAL_REQUESTS_WITHOUT_WANTREPLY);
        action.setExpectedMessages(
                List.of(new VersionExchangeMessage(), new KeyExchangeInitMessage()));
        action.setReceivedMessages(
                List.of(
                        new VersionExchangeMessage(),
                        Optional.of(new GlobalRequestOpenSshHostKeysMessage())
                                .map(
                                        message -> {
                                            message.setWantReply((byte) 0);
                                            return message;
                                        })
                                .get(),
                        new KeyExchangeInitMessage()));
        Assertions.assertTrue(action.executedAsPlanned());
    }

    @Test
    public void
            testExecutedAsPlannedIsFalseWithUnexpectedGlobalRequestMessagesWithWantReplyAndIgnoreUnexpectedGlobalRequestsWithoutWantReplyEnabled() {
        final ReceiveAction action =
                new ReceiveAction(
                        ReceiveOption.IGNORE_UNEXPECTED_GLOBAL_REQUESTS_WITHOUT_WANTREPLY);
        action.setExpectedMessages(
                List.of(new VersionExchangeMessage(), new KeyExchangeInitMessage()));
        action.setReceivedMessages(
                List.of(
                        new VersionExchangeMessage(),
                        Optional.of(new GlobalRequestOpenSshHostKeysMessage())
                                .map(
                                        message -> {
                                            message.setWantReply((byte) 1);
                                            return message;
                                        })
                                .get(),
                        new KeyExchangeInitMessage()));
        Assertions.assertFalse(action.executedAsPlanned());
    }
}
