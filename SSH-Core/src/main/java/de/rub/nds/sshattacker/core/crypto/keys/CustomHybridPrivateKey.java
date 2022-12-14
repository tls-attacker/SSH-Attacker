/* SSH-Attacker - A Modular Penetration Testing Framework for SSH
*
* Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
*
* Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
*/
package de.rub.nds.sshattacker.core.crypto.keys;

import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;


@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class CustomHybridPrivateKey extends CustomPrivateKey {

    private byte[] privateKey;
    private String algorithm;

    @SuppressWarnings("unused")
    private CustomHybridPrivateKey() {
    }

    public CustomHybridPrivateKey(byte[] privateKey, String algorithm) {
        this.privateKey = privateKey;
        this.algorithm = algorithm;
    }

    public byte[] getPrivateKey() {
        return this.privateKey;
    }

    @Override
    public byte[] getEncoded() {
        return this.privateKey;
    }

   @Override
   public String getAlgorithm() {
       return algorithm;
   }
}