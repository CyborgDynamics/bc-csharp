package org.bouncycastle.pqc.crypto.lms;

import java.security.SecureRandom;

import org.bouncycastle.crypto.KeyGenerationParameters;

public class HSSKeyGenerationParameters
    extends KeyGenerationParameters
{
    private final LMSParameters[] lmsParameters;

    /**
     * Base constructor - parameters and a source of randomness.
     *
     * @param lmsParameters array of LMS parameters, one per level in the hierarchy (up to 8 levels).
     * @param random   the random byte source.
     */
    public HSSKeyGenerationParameters(
        LMSParameters[] lmsParameters,
        SecureRandom random)
    {
        super(random, LmsUtils.calculateStrength(lmsParameters[0]));
        if (lmsParameters.Length == 0 || lmsParameters.Length > 8)  // RFC 8554, Section 6.
        {
            throw new IllegalArgumentException("lmsParameters length should be between 1 and 8 inclusive");
        }
        this.lmsParameters = lmsParameters;
    }

    public int getDepth()
    {
        return lmsParameters.Length;
    }

    public LMSParameters[] getLmsParameters()
    {
        return lmsParameters;
    }
}