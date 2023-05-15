/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.ntrup.sntrup.core;

import java.util.Optional;

@SuppressWarnings("StandardVariableNames")
public class SntrupCore {
    private final SntrupParameterSet set;

    public SntrupCore(SntrupParameterSet set) {
        super();
        this.set = set;
    }

    public SntrupCoreValues keyGenCore() {

        R g = null;
        R3 gInv = null;

        while (g == null) {
            R tmp = R.randomSmall(set);
            Optional<R3> tmpInv = R3.getInverseInR3(set, tmp);
            if (tmpInv.isPresent()) {
                g = tmp;
                gInv = tmpInv.get();
            }
        }

        Short f = Short.createRandomShort(set);
        RQ f3 = RQ.multiply(3, f);
        RQ f3Inv = RQ.invert(f3);
        RQ h = RQ.multiply(g, f3Inv);
        Short roh = Short.createRandomShort(set);

        return new SntrupCoreValues(g, gInv, f, f3, f3Inv, h, roh);
    }

    public static Rounded encrypt(Short input, RQ h) {
        RQ hr = RQ.multiply(input, h);
        return Rounded.round(hr);
    }

    public Short decrypt(Rounded ciphertext, Short f, R3 gInv) {
        RQ f3 = RQ.multiply(3, f);
        RQ cf3 = RQ.multiply(ciphertext, f3);
        R3 e = new R3(cf3.getSet(), cf3.stream().toArray());
        R3 ev = R3.multiply(e, gInv);
        R r = R.lift(ev);
        return Short.createShort(set, r.stream().toArray());
    }
}
