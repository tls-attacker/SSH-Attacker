/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.preparator;

import de.rub.nds.sshattacker.core.constants.*;
import de.rub.nds.sshattacker.core.protocol.common.SshMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.transport.message.ExtensionInfoMessage;
import de.rub.nds.sshattacker.core.protocol.transport.message.extension.AbstractExtension;
import de.rub.nds.sshattacker.core.protocol.transport.message.extension.DelayCompressionExtension;
import de.rub.nds.sshattacker.core.protocol.transport.message.extension.ServerSigAlgsExtension;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import java.util.LinkedList;
import java.util.List;

public class ExtensionInfoMessagePreparator extends SshMessagePreparator<ExtensionInfoMessage> {

    public ExtensionInfoMessagePreparator(Chooser chooser, ExtensionInfoMessage message) {
        super(chooser, message, MessageIdConstant.SSH_MSG_EXT_INFO);
    }

    @Override
    public void prepareMessageSpecificContents() {
        // send delay-compression extension by default when acting as client
        if (chooser.getContext().isClient()) {
            chooser.getContext().setClientSupportedExtensions(getDefaultExtensionsForClient());
            getObject().setExtensionCount(chooser.getClientSupportedExtensions().size());
            getObject().setExtensions(chooser.getClientSupportedExtensions());
        }

        // send server-sig-algs and delay-compression extension by default when acting as server
        else {
            chooser.getContext().setServerSupportedExtensions(getDefaultExtensionsForServer());
            getObject().setExtensionCount(chooser.getServerSupportedExtensions().size());
            getObject().setExtensions(chooser.getServerSupportedExtensions());
        }
    }

    private List<AbstractExtension<?>> getDefaultExtensionsForClient() {
        List<AbstractExtension<?>> extensions = new LinkedList<>();
        extensions.add(getDefaultDelayCompressionExtension());
        return extensions;
    }

    public List<AbstractExtension<?>> getDefaultExtensionsForServer() {
        List<AbstractExtension<?>> extensions = new LinkedList<>();
        extensions.add(getDefaultServerSigAlgsExtension());
        extensions.add(getDefaultDelayCompressionExtension());
        return extensions;
    }

    private ServerSigAlgsExtension getDefaultServerSigAlgsExtension() {
        ServerSigAlgsExtension extension = new ServerSigAlgsExtension();
        extension.setNameLength(Extension.SERVER_SIG_ALGS.getName().length());
        extension.setName(Extension.SERVER_SIG_ALGS.getName());

        // valueLength = length of the string
        //
        // "ssh-dss,ssh-rsa,rsa-sha2-256,rsa-sha2-512,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,ssh-ed25519,ecdsa-sha2-1.3.132.0.10"
        int valueLength =
                PublicKeyAlgorithm.SSH_DSS.getName().length()
                        + PublicKeyAlgorithm.SSH_RSA.getName().length()
                        + PublicKeyAlgorithm.RSA_SHA2_256.getName().length()
                        + PublicKeyAlgorithm.RSA_SHA2_512.getName().length()
                        + PublicKeyAlgorithm.ECDSA_SHA2_NISTP256.getName().length()
                        + PublicKeyAlgorithm.ECDSA_SHA2_NISTP384.getName().length()
                        + PublicKeyAlgorithm.ECDSA_SHA2_NISTP521.getName().length()
                        + PublicKeyAlgorithm.SSH_ED25519.getName().length()
                        + PublicKeyAlgorithm.ECDSA_SHA2_SECP256K1.getName().length();

        // value =
        // "ssh-dss,ssh-rsa,rsa-sha2-256,rsa-sha2-512,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,ssh-ed25519,ecdsa-sha2-1.3.132.0.10"
        String value =
                PublicKeyAlgorithm.SSH_DSS.getName()
                        + CharConstants.ALGORITHM_SEPARATOR
                        + PublicKeyAlgorithm.SSH_RSA.getName()
                        + CharConstants.ALGORITHM_SEPARATOR
                        + PublicKeyAlgorithm.RSA_SHA2_256.getName()
                        + CharConstants.ALGORITHM_SEPARATOR
                        + PublicKeyAlgorithm.RSA_SHA2_512.getName()
                        + CharConstants.ALGORITHM_SEPARATOR
                        + PublicKeyAlgorithm.ECDSA_SHA2_NISTP256.getName()
                        + CharConstants.ALGORITHM_SEPARATOR
                        + PublicKeyAlgorithm.ECDSA_SHA2_NISTP384.getName()
                        + CharConstants.ALGORITHM_SEPARATOR
                        + PublicKeyAlgorithm.ECDSA_SHA2_NISTP521.getName()
                        + CharConstants.ALGORITHM_SEPARATOR
                        + PublicKeyAlgorithm.SSH_ED25519.getName()
                        + CharConstants.ALGORITHM_SEPARATOR
                        + PublicKeyAlgorithm.ECDSA_SHA2_SECP256K1.getName();

        extension.setValueLength(valueLength);
        extension.setAcceptedPublicKeyAlgorithmsLength(valueLength);
        extension.setAcceptedPublicKeyAlgorithms(value);
        return extension;
    }

    private DelayCompressionExtension getDefaultDelayCompressionExtension() {
        DelayCompressionExtension extension = new DelayCompressionExtension();
        extension.setNameLength(Extension.DELAY_COMPRESSION.getName().length());
        extension.setName(Extension.DELAY_COMPRESSION.getName());

        // valueLength = length of the string "none,zlib,zlib@openssh.com"
        int valueLength =
                CompressionMethod.NONE.toString().length()
                        + CompressionMethod.ZLIB.toString().length()
                        + CompressionMethod.ZLIB_OPENSSH_COM.toString().length()
                        + 2;

        // value = "none,zlib,zlib@openssh.com"
        String value =
                CompressionMethod.NONE.toString()
                        + CharConstants.ALGORITHM_SEPARATOR
                        + CompressionMethod.ZLIB.toString()
                        + CharConstants.ALGORITHM_SEPARATOR
                        + CompressionMethod.ZLIB_OPENSSH_COM.toString();

        extension.setValueLength(2 * (valueLength + DataFormatConstants.UINT32_SIZE));
        extension.setCompressionMethodsClientToServerLength(valueLength);
        extension.setCompressionMethodsClientToServer(value);
        extension.setCompressionMethodsServerToClientLength(valueLength);
        extension.setCompressionMethodsServerToClient(value);
        return extension;
    }
}
