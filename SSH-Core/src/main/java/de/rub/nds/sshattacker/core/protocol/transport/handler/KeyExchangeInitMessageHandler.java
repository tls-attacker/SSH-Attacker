/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.handler;

import de.rub.nds.sshattacker.core.constants.*;
import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.protocol.common.*;
import de.rub.nds.sshattacker.core.protocol.transport.message.KeyExchangeInitMessage;
import de.rub.nds.sshattacker.core.protocol.util.AlgorithmPicker;
import de.rub.nds.sshattacker.core.util.Converter;
import java.util.Arrays;

public class KeyExchangeInitMessageHandler extends SshMessageHandler<KeyExchangeInitMessage> {

    public KeyExchangeInitMessageHandler(SshContext context) {
        super(context);
    }

    /*public KeyExchangeInitMessageHandler(SshContext context, KeyExchangeInitMessage message) {
        super(context, message);
    }*/

    @Override
    public void adjustContext(KeyExchangeInitMessage message) {
        if (sshContext.isHandleAsClient()) {
            sshContext.setServerCookie(message.getCookie().getValue());
            sshContext.setServerSupportedKeyExchangeAlgorithms(
                    Converter.nameListToEnumValues(
                            message.getKeyExchangeAlgorithms().getValue(),
                            KeyExchangeAlgorithm.class));
            sshContext.setServerSupportedHostKeyAlgorithms(
                    Converter.nameListToEnumValues(
                            message.getServerHostKeyAlgorithms().getValue(),
                            PublicKeyAlgorithm.class));
            sshContext.setServerSupportedEncryptionAlgorithmsClientToServer(
                    Converter.nameListToEnumValues(
                            message.getEncryptionAlgorithmsClientToServer().getValue(),
                            EncryptionAlgorithm.class));
            sshContext.setServerSupportedEncryptionAlgorithmsServerToClient(
                    Converter.nameListToEnumValues(
                            message.getEncryptionAlgorithmsServerToClient().getValue(),
                            EncryptionAlgorithm.class));
            sshContext.setServerSupportedMacAlgorithmsClientToServer(
                    Converter.nameListToEnumValues(
                            message.getMacAlgorithmsClientToServer().getValue(),
                            MacAlgorithm.class));
            sshContext.setServerSupportedMacAlgorithmsServerToClient(
                    Converter.nameListToEnumValues(
                            message.getMacAlgorithmsServerToClient().getValue(),
                            MacAlgorithm.class));
            sshContext.setServerSupportedCompressionMethodsClientToServer(
                    Converter.nameListToEnumValues(
                            message.getCompressionMethodsClientToServer().getValue(),
                            CompressionMethod.class));
            sshContext.setServerSupportedCompressionMethodsServerToClient(
                    Converter.nameListToEnumValues(
                            message.getCompressionMethodsServerToClient().getValue(),
                            CompressionMethod.class));
            sshContext.setServerSupportedLanguagesClientToServer(
                    Arrays.asList(
                            message.getLanguagesClientToServer()
                                    .getValue()
                                    .split("" + CharConstants.ALGORITHM_SEPARATOR)));
            sshContext.setServerSupportedLanguagesServerToClient(
                    Arrays.asList(
                            message.getLanguagesServerToClient()
                                    .getValue()
                                    .split("" + CharConstants.ALGORITHM_SEPARATOR)));
            sshContext.setServerReserved(message.getReserved().getValue());

            sshContext.getExchangeHashInputHolder().setServerKeyExchangeInit(message);
        } else {
            sshContext.setClientCookie(message.getCookie().getValue());
            sshContext.setClientSupportedKeyExchangeAlgorithms(
                    Converter.nameListToEnumValues(
                            message.getKeyExchangeAlgorithms().getValue(),
                            KeyExchangeAlgorithm.class));
            sshContext.setClientSupportedHostKeyAlgorithms(
                    Converter.nameListToEnumValues(
                            message.getServerHostKeyAlgorithms().getValue(),
                            PublicKeyAlgorithm.class));
            sshContext.setClientSupportedEncryptionAlgorithmsClientToServer(
                    Converter.nameListToEnumValues(
                            message.getEncryptionAlgorithmsClientToServer().getValue(),
                            EncryptionAlgorithm.class));
            sshContext.setClientSupportedEncryptionAlgorithmsServerToClient(
                    Converter.nameListToEnumValues(
                            message.getEncryptionAlgorithmsServerToClient().getValue(),
                            EncryptionAlgorithm.class));
            sshContext.setClientSupportedMacAlgorithmsClientToServer(
                    Converter.nameListToEnumValues(
                            message.getMacAlgorithmsClientToServer().getValue(),
                            MacAlgorithm.class));
            sshContext.setClientSupportedMacAlgorithmsServerToClient(
                    Converter.nameListToEnumValues(
                            message.getMacAlgorithmsServerToClient().getValue(),
                            MacAlgorithm.class));
            sshContext.setClientSupportedCompressionMethodsClientToServer(
                    Converter.nameListToEnumValues(
                            message.getCompressionMethodsClientToServer().getValue(),
                            CompressionMethod.class));
            sshContext.setClientSupportedCompressionMethodsServerToClient(
                    Converter.nameListToEnumValues(
                            message.getCompressionMethodsServerToClient().getValue(),
                            CompressionMethod.class));
            sshContext.setClientSupportedLanguagesClientToServer(
                    Arrays.asList(
                            message.getLanguagesClientToServer()
                                    .getValue()
                                    .split("" + CharConstants.ALGORITHM_SEPARATOR)));
            sshContext.setClientSupportedLanguagesServerToClient(
                    Arrays.asList(
                            message.getLanguagesServerToClient()
                                    .getValue()
                                    .split("" + CharConstants.ALGORITHM_SEPARATOR)));
            sshContext.setClientReserved(message.getReserved().getValue());

            sshContext.getExchangeHashInputHolder().setClientKeyExchangeInit(message);
        }

        pickAlgorithms();
    }

    private void pickAlgorithms() {

        // if enforceSettings is true, the algorithms are expected to be
        // already set in the context
        if (!sshContext.getConfig().getEnforceSettings()) {
            sshContext.setKeyExchangeAlgorithm(
                    AlgorithmPicker.pickAlgorithm(
                                    sshContext
                                            .getChooser()
                                            .getClientSupportedKeyExchangeAlgorithms(),
                                    sshContext
                                            .getChooser()
                                            .getServerSupportedKeyExchangeAlgorithms())
                            .orElse(null));

            sshContext.setEncryptionAlgorithmClientToServer(
                    AlgorithmPicker.pickAlgorithm(
                                    sshContext
                                            .getChooser()
                                            .getClientSupportedEncryptionAlgorithmsClientToServer(),
                                    sshContext
                                            .getChooser()
                                            .getServerSupportedEncryptionAlgorithmsClientToServer())
                            .orElse(null));

            sshContext.setEncryptionAlgorithmServerToClient(
                    AlgorithmPicker.pickAlgorithm(
                                    sshContext
                                            .getChooser()
                                            .getClientSupportedEncryptionAlgorithmsServerToClient(),
                                    sshContext
                                            .getChooser()
                                            .getServerSupportedEncryptionAlgorithmsServerToClient())
                            .orElse(null));

            sshContext.setHostKeyAlgorithm(
                    AlgorithmPicker.pickAlgorithm(
                                    sshContext.getChooser().getClientSupportedHostKeyAlgorithms(),
                                    sshContext.getChooser().getServerSupportedHostKeyAlgorithms())
                            .orElse(null));

            sshContext.setMacAlgorithmClientToServer(
                    AlgorithmPicker.pickAlgorithm(
                                    sshContext
                                            .getChooser()
                                            .getClientSupportedMacAlgorithmsClientToServer(),
                                    sshContext
                                            .getChooser()
                                            .getServerSupportedMacAlgorithmsClientToServer())
                            .orElse(null));

            sshContext.setMacAlgorithmServerToClient(
                    AlgorithmPicker.pickAlgorithm(
                                    sshContext
                                            .getChooser()
                                            .getClientSupportedMacAlgorithmsServerToClient(),
                                    sshContext
                                            .getChooser()
                                            .getServerSupportedMacAlgorithmsServerToClient())
                            .orElse(null));

            sshContext.setCompressionMethodClientToServer(
                    AlgorithmPicker.pickAlgorithm(
                                    sshContext
                                            .getChooser()
                                            .getClientSupportedCompressionMethodsClientToServer(),
                                    sshContext
                                            .getChooser()
                                            .getServerSupportedCompressionMethodsClientToServer())
                            .orElse(null));

            sshContext.setCompressionMethodServerToClient(
                    AlgorithmPicker.pickAlgorithm(
                                    sshContext
                                            .getChooser()
                                            .getClientSupportedCompressionMethodsServerToClient(),
                                    sshContext
                                            .getChooser()
                                            .getServerSupportedCompressionMethodsServerToClient())
                            .orElse(null));
        }

        LOGGER.info(
                "[bro] Picking KEX Algorithm, Setting Hostkey to {}",
                sshContext.getHostKeyAlgorithm());
    }

    /*@Override
    public KeyExchangeInitMessageParser getParser(byte[] array) {
        return new KeyExchangeInitMessageParser(array);
    }

    @Override
    public KeyExchangeInitMessageParser getParser(byte[] array, int startPosition) {
        return new KeyExchangeInitMessageParser(array, startPosition);
    }

    @Override
    public KeyExchangeInitMessagePreparator getPreparator() {
        return new KeyExchangeInitMessagePreparator(context.getChooser(), message);
    }

    @Override
    public KeyExchangeInitMessageSerializer getSerializer() {
        return new KeyExchangeInitMessageSerializer(message);
    }*/
}
