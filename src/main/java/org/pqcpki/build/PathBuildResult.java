package org.pqcpki.build;

import org.pqcpki.algo.AlgorithmSpec;
import org.pqcpki.measure.Stats;

/**
 * What one path-building measurement produced.
 *
 * @param scenario         scenario name (e.g. {@code branching-k8}, {@code federal-bridge})
 * @param algorithm        the algorithm every certificate was signed with
 * @param candidateIssuers the branching factor — how many issuer certificates the bridged name carried
 * @param poolSize         number of certificates in the store the builder searched
 * @param poolBytes        total bytes of that store
 * @param pathLength       length of the discovered path
 * @param buildMicros      per-build time distribution
 */
public record PathBuildResult(
        String scenario,
        AlgorithmSpec algorithm,
        int candidateIssuers,
        int poolSize,
        int poolBytes,
        int pathLength,
        Stats buildMicros) {
}
