/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.common;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.fail;

import de.rub.nds.sshattacker.core.exceptions.NotImplementedException;
import de.rub.nds.sshattacker.core.exceptions.ParserException;
import de.rub.nds.sshattacker.core.exceptions.PreparationException;
import de.rub.nds.sshattacker.core.protocol.transport.message.*;
import de.rub.nds.sshattacker.core.state.SshContext;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Modifier;
import java.security.Security;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Stream;
import org.apache.commons.lang3.SerializationException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Before;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;
import org.junit.jupiter.api.function.Executable;
import org.opentest4j.TestAbortedException;
import org.reflections.Reflections;

@SuppressWarnings("rawtypes")
public class CyclicParserSerializerTest {

    private static final Logger LOGGER = LogManager.getLogger();

    @Before
    public void setUp() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @TestFactory
    public Stream<DynamicTest> generateCyclicDefaultConstructorPairsDynamicTests() {
        Set<Class<? extends ProtocolMessage>> excludedClasses = new HashSet<>();
        // Exclude UnknownMessage as it is not a standardized protocol message (it is only used when
        // a message could not be parsed successfully)
        excludedClasses.add(UnknownMessage.class);
        return new Reflections("de.rub.nds.sshattacker.core.protocol")
                .getSubTypesOf(ProtocolMessage.class).stream()
                        .filter(messageClass -> !Modifier.isAbstract(messageClass.getModifiers()))
                        .filter(messageClass -> !excludedClasses.contains(messageClass))
                        .map(
                                messageClass ->
                                        DynamicTest.dynamicTest(
                                                "CyclicDefaultConstructorPairsTest{"
                                                        + messageClass.getSimpleName()
                                                        + "}",
                                                new CyclicDefaultConstructorPairsTest(
                                                        messageClass)));
    }

    private static class CyclicDefaultConstructorPairsTest implements Executable {

        private final Class<? extends ProtocolMessage> messageClass;
        private final String messageClassName;

        private CyclicDefaultConstructorPairsTest(Class<? extends ProtocolMessage> messageClass) {
            this.messageClass = messageClass;
            this.messageClassName = messageClass.getSimpleName();
        }

        @Override
        public void execute() {
            LOGGER.info("Testing ProtocolMessage subclass: " + messageClassName);

            // Construct a new instance of the message class to test
            ProtocolMessage message = null;
            try {
                Constructor someMessageConstructor = getDefaultMessageConstructor(messageClass);
                if (someMessageConstructor != null) {
                    message = (ProtocolMessage) someMessageConstructor.newInstance();
                } else {
                    fail(
                            "Subclass '"
                                    + messageClassName
                                    + "' does not have a default constructor.");
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

            // Create a fresh SshContext
            SshContext context = new SshContext();

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
            ProtocolMessage parsedMessage = null;
            try {
                parsedMessage = message.getHandler(context).getParser(serializedMessage, 0).parse();
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

            // TODO: Implement equals() / hashCode() for all message classes and uncomment the
            // following two assertions
            // On the other hand message should equal parsedMessage
            // This validates the order serialize -> parse as well as the equals() / hashCode()
            // methods on the class
            // assertEquals(message, parsedMessage);
            // assertEquals(message.hashCode(), parsedMessage.hashCode());
        }

        private static Constructor<?> getDefaultMessageConstructor(Class<?> someClass) {
            for (Constructor<?> c : someClass.getDeclaredConstructors()) {
                if (c.getParameterCount() == 0) {
                    return c;
                }
            }
            LOGGER.warn(
                    "Unable to find default constructor for class: " + someClass.getSimpleName());
            return null;
        }
    }
}
