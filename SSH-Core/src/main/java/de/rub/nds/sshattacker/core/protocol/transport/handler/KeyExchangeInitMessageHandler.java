/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.handler;

import de.rub.nds.sshattacker.core.constants.*;
import de.rub.nds.sshattacker.core.protocol.common.*;
import de.rub.nds.sshattacker.core.protocol.transport.message.KeyExchangeInitMessage;
import de.rub.nds.sshattacker.core.protocol.transport.parser.KeyExchangeInitMessageParser;
import de.rub.nds.sshattacker.core.protocol.transport.preparator.KeyExchangeInitMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.transport.serializer.KeyExchangeInitMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.util.AlgorithmPicker;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.util.Converter;
import java.util.Arrays;

public class KeyExchangeInitMessageHandler extends SshMessageHandler<KeyExchangeInitMessage> {

    public KeyExchangeInitMessageHandler(SshContext context) {
        super(context);
    }

    public KeyExchangeInitMessageHandler(SshContext context, KeyExchangeInitMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {
        if (context.isClient()) {
            context.setServerCookie(message.getCookie().getValue());
            context.setServerSupportedKeyExchangeAlgorithms(
                    Converter.stringToAlgorithms(
                            message.getKeyExchangeAlgorithms().getValue(),
                            KeyExchangeAlgorithm.class));
            context.setServerSupportedHostKeyAlgorithms(
                    Converter.stringToAlgorithms(
                            message.getServerHostKeyAlgorithms().getValue(),
                            PublicKeyAuthenticationAlgorithm.class));
            context.setServerSupportedCipherAlgorithmsClientToServer(
                    Converter.stringToAlgorithms(
                            message.getEncryptionAlgorithmsClientToServer().getValue(),
                            EncryptionAlgorithm.class));
            context.setServerSupportedCipherAlgorithmsServerToClient(
                    Converter.stringToAlgorithms(
                            message.getEncryptionAlgorithmsServerToClient().getValue(),
                            EncryptionAlgorithm.class));
            context.setServerSupportedMacAlgorithmsClientToServer(
                    Converter.stringToAlgorithms(
                            message.getMacAlgorithmsClientToServer().getValue(),
                            MacAlgorithm.class));
            context.setServerSupportedMacAlgorithmsServerToClient(
                    Converter.stringToAlgorithms(
                            message.getMacAlgorithmsServerToClient().getValue(),
                            MacAlgorithm.class));
            context.setServerSupportedCompressionAlgorithmsClientToServer(
                    Converter.stringToAlgorithms(
                            message.getCompressionAlgorithmsClientToServer().getValue(),
                            CompressionAlgorithm.class));
            context.setServerSupportedCompressionAlgorithmsServerToClient(
                    Converter.stringToAlgorithms(
                            message.getCompressionAlgorithmsServerToClient().getValue(),
                            CompressionAlgorithm.class));
            context.setServerSupportedLanguagesClientToServer(
                    Arrays.asList(
                            message.getLanguagesClientToServer()
                                    .getValue()
                                    .split("" + CharConstants.ALGORITHM_SEPARATOR)));
            context.setServerSupportedLanguagesServerToClient(
                    Arrays.asList(
                            message.getLanguagesServerToClient()
                                    .getValue()
                                    .split("" + CharConstants.ALGORITHM_SEPARATOR)));
            context.setServerReserved(message.getReserved().getValue());

            context.getExchangeHashInstance().setServerKeyExchangeInit(message);
        } else {
            context.setClientCookie(message.getCookie().getValue());
            context.setClientSupportedKeyExchangeAlgorithms(
                    Converter.stringToAlgorithms(
                            message.getKeyExchangeAlgorithms().getValue(),
                            KeyExchangeAlgorithm.class));
            context.setClientSupportedHostKeyAlgorithms(
                    Converter.stringToAlgorithms(
                            message.getServerHostKeyAlgorithms().getValue(),
                            PublicKeyAuthenticationAlgorithm.class));
            context.setClientSupportedCipherAlgorithmsClientToServer(
                    Converter.stringToAlgorithms(
                            message.getEncryptionAlgorithmsClientToServer().getValue(),
                            EncryptionAlgorithm.class));
            context.setClientSupportedCipherAlgorithmsServerToClient(
                    Converter.stringToAlgorithms(
                            message.getEncryptionAlgorithmsServerToClient().getValue(),
                            EncryptionAlgorithm.class));
            context.setClientSupportedMacAlgorithmsClientToServer(
                    Converter.stringToAlgorithms(
                            message.getMacAlgorithmsClientToServer().getValue(),
                            MacAlgorithm.class));
            context.setClientSupportedMacAlgorithmsServerToClient(
                    Converter.stringToAlgorithms(
                            message.getMacAlgorithmsServerToClient().getValue(),
                            MacAlgorithm.class));
            context.setClientSupportedCompressionAlgorithmsClientToServer(
                    Converter.stringToAlgorithms(
                            message.getCompressionAlgorithmsClientToServer().getValue(),
                            CompressionAlgorithm.class));
            context.setClientSupportedCompressionAlgorithmsServerToClient(
                    Converter.stringToAlgorithms(
                            message.getCompressionAlgorithmsServerToClient().getValue(),
                            CompressionAlgorithm.class));
            context.setClientSupportedLanguagesClientToServer(
                    Arrays.asList(
                            message.getLanguagesClientToServer()
                                    .getValue()
                                    .split("" + CharConstants.ALGORITHM_SEPARATOR)));
            context.setClientSupportedLanguagesServerToClient(
                    Arrays.asList(
                            message.getLanguagesServerToClient()
                                    .getValue()
                                    .split("" + CharConstants.ALGORITHM_SEPARATOR)));
            context.setClientReserved(message.getReserved().getValue());

            context.getExchangeHashInstance().setClientKeyExchangeInit(message);
        }

        pickAlgorithms();
    }

    private void pickAlgorithms() {
        // if enforceSettings is true, the algorithms are expected to be
        // already set in the context
        if (!context.getConfig().getEnforceSettings()) {
            context.setKeyExchangeAlgorithm(
                    AlgorithmPicker.pickAlgorithm(
                                    context.getChooser().getClientSupportedKeyExchangeAlgorithms(),
                                    context.getChooser().getServerSupportedKeyExchangeAlgorithms())
                            .orElse(null));

            context.setCipherAlgorithmClientToServer(
                    AlgorithmPicker.pickAlgorithm(
                                    context.getChooser()
                                            .getClientSupportedCipherAlgorithmsClientToServer(),
                                    context.getChooser()
                                            .getServerSupportedCipherAlgorithmsClientToServer())
                            .orElse(null));

            context.setCipherAlgorithmServerToClient(
                    AlgorithmPicker.pickAlgorithm(
                                    context.getChooser()
                                            .getClientSupportedCipherAlgorithmsServerToClient(),
                                    context.getChooser()
                                            .getServerSupportedCipherAlgorithmsServerToClient())
                            .orElse(null));

            context.setServerHostKeyAlgorithm(
                    AlgorithmPicker.pickAlgorithm(
                                    context.getChooser().getClientSupportedHostKeyAlgorithms(),
                                    context.getChooser().getServerSupportedHostKeyAlgorithms())
                            .orElse(null));

            context.setMacAlgorithmClientToServer(
                    AlgorithmPicker.pickAlgorithm(
                                    context.getChooser()
                                            .getClientSupportedMacAlgorithmsClientToServer(),
                                    context.getChooser()
                                            .getServerSupportedMacAlgorithmsClientToServer())
                            .orElse(null));

            context.setMacAlgorithmServerToClient(
                    AlgorithmPicker.pickAlgorithm(
                                    context.getChooser()
                                            .getClientSupportedMacAlgorithmsServerToClient(),
                                    context.getChooser()
                                            .getServerSupportedMacAlgorithmsServerToClient())
                            .orElse(null));

            context.setCompressionAlgorithmClientToServer(
                    AlgorithmPicker.pickAlgorithm(
                                    context.getChooser()
                                            .getClientSupportedCompressionAlgorithmsClientToServer(),
                                    context.getChooser()
                                            .getServerSupportedCompressionAlgorithmsClientToServer())
                            .orElse(null));

            context.setCompressionAlgorithmServerToClient(
                    AlgorithmPicker.pickAlgorithm(
                                    context.getChooser()
                                            .getClientSupportedCompressionAlgorithmsServerToClient(),
                                    context.getChooser()
                                            .getServerSupportedCompressionAlgorithmsServerToClient())
                            .orElse(null));
        }
    }

    @Override
    public KeyExchangeInitMessageParser getParser(byte[] array, int startPosition) {
        return new KeyExchangeInitMessageParser(array, startPosition);
    }

    @Override
    public KeyExchangeInitMessagePreparator getPreparator() {
        return new KeyExchangeInitMessagePreparator(context, message);
    }

    @Override
    public KeyExchangeInitMessageSerializer getSerializer() {
        return new KeyExchangeInitMessageSerializer(message);
    }
}
