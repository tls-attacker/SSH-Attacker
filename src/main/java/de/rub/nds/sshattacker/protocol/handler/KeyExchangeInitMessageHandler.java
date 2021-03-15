package de.rub.nds.sshattacker.protocol.handler;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.constants.CompressionAlgorithm;
import de.rub.nds.sshattacker.constants.EncryptionAlgorithm;
import de.rub.nds.sshattacker.constants.KeyExchangeAlgorithm;
import de.rub.nds.sshattacker.constants.Language;
import de.rub.nds.sshattacker.constants.MacAlgorithm;
import de.rub.nds.sshattacker.constants.MessageIDConstant;
import de.rub.nds.sshattacker.constants.PublicKeyAuthenticationAlgorithm;
import de.rub.nds.sshattacker.protocol.AlgorithmPicker;
import de.rub.nds.sshattacker.protocol.message.KeyExchangeInitMessage;
import de.rub.nds.sshattacker.protocol.serializer.KeyExchangeInitMessageSerializer;
import de.rub.nds.sshattacker.state.SshContext;
import de.rub.nds.sshattacker.util.Converter;

public class KeyExchangeInitMessageHandler extends Handler<KeyExchangeInitMessage> {

    public KeyExchangeInitMessageHandler(SshContext context) {
        super(context);
    }

    @Override
    public void handle(KeyExchangeInitMessage message) {
        context.setServerCookie(message.getCookie().getValue());
        context.setServerSupportedKeyExchangeAlgorithms(Converter.StringToAlgorithms(message.getKeyExchangeAlgorithms().getValue(), KeyExchangeAlgorithm.class));
        context.setServerSupportedHostKeyAlgorithms(Converter.StringToAlgorithms(message.getServerHostKeyAlgorithms().getValue(), PublicKeyAuthenticationAlgorithm.class));
        context.setServerSupportedCipherAlgorithmsClientToServer(Converter.StringToAlgorithms(message.getEncryptionAlgorithmsClientToServer().getValue(), EncryptionAlgorithm.class));
        context.setServerSupportedCipherAlgorithmsServerToClient(Converter.StringToAlgorithms(message.getEncryptionAlgorithmsServerToClient().getValue(), EncryptionAlgorithm.class));
        context.setServerSupportedMacAlgorithmsClientToServer(Converter.StringToAlgorithms(message.getMacAlgorithmsClientToServer().getValue(), MacAlgorithm.class));
        context.setServerSupportedMacAlgorithmsServerToClient(Converter.StringToAlgorithms(message.getMacAlgorithmsServerToClient().getValue(), MacAlgorithm.class));
        context.setServerSupportedCompressionAlgorithmsClientToServer(Converter.StringToAlgorithms(message.getCompressionAlgorithmsClientToServer().getValue(), CompressionAlgorithm.class));
        context.setServerSupportedCompressionAlgorithmsServerToClient(Converter.StringToAlgorithms(message.getCompressionAlgorithmsServerToClient().getValue(), CompressionAlgorithm.class));
        context.setServerSupportedLanguagesClientToServer(Converter.StringToAlgorithms(message.getLanguagesClientToServer().getValue(), Language.class));
        context.setServerSupportedLanguagesServerToClient(Converter.StringToAlgorithms(message.getLanguagesServerToClient().getValue(), Language.class));
        context.setServerReserved(message.getReserved().getValue());

        adjustAlgorithms();

        context.appendToExchangeHashInput(ArrayConverter.concatenate(new byte[]{MessageIDConstant.SSH_MSG_KEXINIT.id},
                new KeyExchangeInitMessageSerializer(message).serializeMessageSpecificPayload()));

    }

    private void adjustAlgorithms() {
        // if enforceSettings is true, the algorithms are expected to be
        // already set in the context
        if (!context.getConfig().getEnforceSettings()) {
            context.setKeyExchangeAlgorithm(
                    AlgorithmPicker.pickAlgorithm(
                            context.getChooser().getClientSupportedKeyExchangeAlgorithms(),
                            context.getChooser().getServerSupportedKeyExchangeAlgorithms()).get());

            context.setCipherAlgorithmClientToServer(
                    AlgorithmPicker.pickAlgorithm(
                            context.getChooser().getClientSupportedCipherAlgorithmsClientToServer(),
                            context.getChooser().getServerSupportedCipherAlgorithmsClientToServer()).get());

            context.setCipherAlgorithmServerToClient(
                    AlgorithmPicker.pickAlgorithm(
                            context.getChooser().getClientSupportedCipherAlgorithmsServertoClient(),
                            context.getChooser().getServerSupportedCipherAlgorithmsServerToClient()).get());

            context.setServerHostKeyAlgorithm(
                    AlgorithmPicker.pickAlgorithm(context.getChooser().getClientSupportedHostKeyAlgorithms(),
                            context.getChooser().getServerSupportedHostKeyAlgorithms()).get());

            context.setMacAlgorithmClientToServer(
                    AlgorithmPicker.pickAlgorithm(
                            context.getChooser().getClientSupportedMacAlgorithmsClientToServer(),
                            context.getChooser().getServerSupportedMacAlgorithmsClientToServer()).get());

            context.setMacAlgorithmServerToClient(
                    AlgorithmPicker.pickAlgorithm(
                            context.getChooser().getClientSupportedMacAlgorithmsServerToClient(),
                            context.getChooser().getServerSupportedMacAlgorithmsServerToClient()).get());

            context.setCompressionAlgorithmClientToServer(
                    AlgorithmPicker.pickAlgorithm(
                            context.getChooser().getClientSupportedCompressionAlgorithmsClientToServer(),
                            context.getChooser().getServerSupportedCompressionAlgorithmsClientToServer()).get());

            context.setCompressionAlgorithmServerToClient(
                    AlgorithmPicker.pickAlgorithm(
                            context.getChooser().getClientSupportedCompressionAlgorithmsServerToClient(),
                            context.getChooser().getServerSupportedCompressionAlgorithmsServerToClient()).get());

            context.setLanguageClientToServer(
                    AlgorithmPicker.pickAlgorithm(
                            context.getChooser().getClientSupportedLanguagesClientToServer(),
                            context.getChooser().getServerSupportedLanguagesServerToClient()).get());

            context.setLanguageServerToClient(
                    AlgorithmPicker.pickAlgorithm(
                            context.getChooser().getClientSupportedLanguagesServerToClient(),
                            context.getChooser().getServerSupportedLanguagesServerToClient()).get());
        }
    }
}
