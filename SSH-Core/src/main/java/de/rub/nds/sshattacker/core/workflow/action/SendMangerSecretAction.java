/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.workflow.action;

import de.rub.nds.modifiablevariable.bytearray.ByteArrayModificationFactory;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.sshattacker.core.crypto.kex.RsaKeyExchange;
import de.rub.nds.sshattacker.core.crypto.keys.CustomRsaPublicKey;
import de.rub.nds.sshattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.sshattacker.core.protocol.common.ProtocolMessage;
import de.rub.nds.sshattacker.core.protocol.transport.message.RsaKeyExchangeSecretMessage;
import de.rub.nds.sshattacker.core.state.State;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

/** Custom Action for dynamically creating and sending {@link RsaKeyExchangeSecretMessage}s */
public class SendMangerSecretAction extends SendAction {

    private static final Logger LOGGER = LogManager.getLogger();

    private final byte[] encodedSecret;

    /** Creates the action using the default connection alias */
    public SendMangerSecretAction() {
        this(new byte[0]);
    }

    /**
     * Creates the action using a custom connection alias
     *
     * @param connectionAlias The custom connection alias
     */
    public SendMangerSecretAction(String connectionAlias) {
        this(new byte[0], connectionAlias);
    }

    /**
     * Creates the action using the default connection alias
     *
     * @param encodedSecret The OAEP encoded shared secret
     */
    public SendMangerSecretAction(byte[] encodedSecret) {
        super();
        this.encodedSecret = encodedSecret;
    }

    /**
     * Creates the action using a custom connection alias
     *
     * @param encodedSecret The OAEP encoded shared secret
     * @param connectionAlias The custom connection alias
     */
    public SendMangerSecretAction(byte[] encodedSecret, String connectionAlias) {
        super(connectionAlias);
        this.encodedSecret = encodedSecret;
    }

    @Override
    public void execute(State state) throws WorkflowExecutionException {
        messages = new ArrayList<>();
        messages.add(createSecretMessage(state));
        super.execute(state);
    }

    /** Creates an {@link RsaKeyExchangeSecretMessage} by encrypting the shared secret with RSA */
    private RsaKeyExchangeSecretMessage createSecretMessage(State state) {
        RsaKeyExchangeSecretMessage message = new RsaKeyExchangeSecretMessage();
        ModifiableByteArray encryptedSecretArray = new ModifiableByteArray();
        Chooser chooser = state.getSshContext().getChooser();
        RsaKeyExchange keyExchange = chooser.getRsaKeyExchange();
        CustomRsaPublicKey publicKey = keyExchange.getTransientKey().getPublicKey();

        try {
            // Encrypt the encoded secret with plain RSA
            Cipher rsa = Cipher.getInstance("RSA/NONE/NoPadding");
            LOGGER.debug("Provider: " + rsa.getProvider());
            rsa.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[] encryptedSecret = rsa.doFinal(encodedSecret);
            encryptedSecretArray.setModification(
                    ByteArrayModificationFactory.explicitValue(encryptedSecret));
            message.setEncryptedSecret(encryptedSecretArray, true);
            return message;

        } catch (NoSuchPaddingException
                | NoSuchAlgorithmException
                | InvalidKeyException
                | IllegalBlockSizeException
                | BadPaddingException e) {
            throw new WorkflowExecutionException("Failed to encrypt encoded secret", e);
        }
    }

    @Override
    public String toString() {
        StringBuilder sb;
        if (isExecuted()) {
            sb = new StringBuilder("Send Manger Secret Action:\n");
        } else {
            sb = new StringBuilder("Send Manger Secret Action: (not executed)\n");
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
