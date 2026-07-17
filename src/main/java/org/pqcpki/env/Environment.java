package org.pqcpki.env;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

/** The facts about the running JVM and library that every result must carry to be reproducible. */
public final class Environment {

    private Environment() {
    }

    /** The BouncyCastle version under measurement, read from the provider rather than assumed. */
    public static String bouncyCastleVersion() {
        return String.valueOf(new BouncyCastleProvider().getVersionStr());
    }

    /** A one-line description of the JVM. */
    public static String jvm() {
        return System.getProperty("java.vm.name")
                + " " + System.getProperty("java.version")
                + " (" + System.getProperty("java.vendor") + ")";
    }

    /** A one-line description of the host, recorded because timing figures are host-specific. */
    public static String host() {
        return System.getProperty("os.name")
                + " " + System.getProperty("os.version")
                + " " + System.getProperty("os.arch")
                + ", " + Runtime.getRuntime().availableProcessors() + " cpus";
    }
}
