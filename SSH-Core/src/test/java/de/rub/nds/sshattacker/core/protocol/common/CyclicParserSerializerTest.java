/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.common;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.fail;

import de.rub.nds.sshattacker.core.exceptions.NotImplementedException;
import de.rub.nds.sshattacker.core.exceptions.ParserException;
import de.rub.nds.sshattacker.core.exceptions.PreparationException;
import de.rub.nds.sshattacker.core.protocol.connection.Channel;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelMessage;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelOpenMessage;
import de.rub.nds.sshattacker.core.state.SshContext;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Modifier;
import java.security.Security;
import java.util.stream.Stream;
import org.apache.commons.lang3.SerializationException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;
import org.junit.jupiter.api.function.Executable;
import org.opentest4j.TestAbortedException;
import org.reflections.Reflections;

public class CyclicParserSerializerTest {

    private static final Logger LOGGER = LogManager.getLogger();

    @BeforeAll
    public static void setUpClass() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @TestFactory
    public Stream<DynamicTest> generateCyclicDefaultConstructorPairsDynamicTests() {
        // Set<Class<? extends ProtocolMessage<?>>> excludedClasses = new HashSet<>();
        return new Reflections("de.rub.nds.sshattacker.core")
                .getSubTypesOf(ProtocolMessage.class).stream()
                        .filter(messageClass -> !Modifier.isAbstract(messageClass.getModifiers()))
                        // .filter(messageClass -> !excludedClasses.contains(messageClass))
                        .map(
                                messageClass ->
                                        DynamicTest.dynamicTest(
                                                "CyclicDefaultConstructorPairsTest{"
                                                        + messageClass.getSimpleName()
                                                        + "}",
                                                new CyclicDefaultConstructorPairsTest(
                                                        messageClass)));
    }

    private static final class CyclicDefaultConstructorPairsTest implements Executable {

        private final Class<?> messageClass;
        private final String messageClassName;

        private CyclicDefaultConstructorPairsTest(Class<?> messageClass) {
            super();
            this.messageClass = messageClass;
            messageClassName = messageClass.getSimpleName();
            if (!ProtocolMessage.class.isAssignableFrom(messageClass)) {
                throw new IllegalArgumentException(
                        "CyclicDefaultConstructorPairsTest is intended for ProtocolMessage subclasses only, but we received class "
                                + messageClass.getSimpleName());
            }
        }

        @Override
        public void execute() {
            LOGGER.info("Testing ProtocolMessage subclass: {}", messageClassName);

            // Construct a new instance of the message class to test
            ProtocolMessage<?> message = null;
            // Create a fresh SshContext
            SshContext context = new SshContext();
            try {
                Constructor<?> someMessageConstructor;

                someMessageConstructor = getDefaultMessageConstructor(messageClass);
                if (someMessageConstructor == null) {
                    fail(
                            "Subclass '"
                                    + messageClassName
                                    + "' does not have the needed constructor.");
                } else {
                    message = (ProtocolMessage<?>) someMessageConstructor.newInstance();
                }
            } catch (SecurityException
                    | InstantiationException
                    | IllegalAccessException
                    | IllegalArgumentException
                    | InvocationTargetException e) {
                LOGGER.fatal(e);
                fail(
                        "Unable to construct message instance for subclass '"
                                + messageClassName
                                + "'");
            }
            // prepare specific Channel requirements for sending Channel messages
            if (ChannelMessage.class.isAssignableFrom(messageClass)
                    || ChannelOpenMessage.class.isAssignableFrom(messageClass)) {
                Channel defaultChannel =
                        context.getConfig().getChannelDefaults().newChannelFromDefaults();
                context.getChannelManager().addChannel(defaultChannel);
                defaultChannel.setOpen(true);
            }
            // Prepare the message given the fresh context
            try {
                message.getHandler(context).getPreparator().prepare();
            } catch (PreparationException e) {
                LOGGER.fatal(e);
                fail(
                        "Caught a PreparationException while preparing message of class '"
                                + messageClassName
                                + "'");
            } catch (NotImplementedException e) {
                LOGGER.error(e);
                throw new TestAbortedException(
                        "Unable to prepare message of class '"
                                + messageClassName
                                + "' - handler or preparator not implemented",
                        e);
            }

            // Serialize message into a byte array
            byte[] serializedMessage = null;
            try {
                serializedMessage = message.getHandler(context).getSerializer().serialize();
            } catch (SerializationException e) {
                LOGGER.fatal(e);
                fail(
                        "Caught a SerializationException while serializing message of class '"
                                + messageClassName
                                + "'");
            } catch (NotImplementedException e) {
                LOGGER.fatal(e);
                throw new TestAbortedException(
                        "Unable to serialize message of class '"
                                + messageClassName
                                + "' - serializer not implemented",
                        e);
            }

            // Parse the serialized message back into a new instance
            ProtocolMessage<?> parsedMessage = null;
            try {
                parsedMessage = message.getHandler(context).getParser(serializedMessage).parse();
            } catch (ParserException e) {
                LOGGER.fatal(e);
                fail(
                        "Caught a ParserException while parsing message of class '"
                                + messageClassName
                                + "'");
            } catch (NotImplementedException e) {
                LOGGER.fatal(e);
                throw new TestAbortedException(
                        "Unable to parse message of class '"
                                + messageClassName
                                + "' - parser not implemented",
                        e);
            }

            // Serializing the parsedMessage again should result in the same bytes as
            // serializedMessage
            // This validates the order parse -> serialize
            try {
                assertArrayEquals(
                        serializedMessage,
                        parsedMessage.getHandler(context).getSerializer().serialize());
            } catch (SerializationException e) {
                LOGGER.fatal(e);
                fail(
                        "Caught a SerializationException during the second serialization of class '"
                                + messageClassName
                                + "'");
            }

            // TODO: Implement equals() / hashCode() for all message classes
        }

        private static Constructor<?> getDefaultMessageConstructor(Class<?> someClass) {
            for (Constructor<?> constructor : someClass.getDeclaredConstructors()) {
                if (constructor.getParameterCount() == 0) {
                    return constructor;
                }
            }
            LOGGER.warn(
                    "Unable to find default constructor for class: {}", someClass.getSimpleName());
            return null;
        }
    }
}
