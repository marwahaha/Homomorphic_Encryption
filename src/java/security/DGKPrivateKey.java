package java.security;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.math.BigInteger;
import java.util.HashMap;

public class DGKPrivateKey implements Serializable, PrivateKey
{
    private static final long serialVersionUID = PrivateKey.serialVersionUID;

    private BigInteger p;
    private BigInteger q;
    private BigInteger vp;
    private BigInteger vq;
    private long u;
    private HashMap <BigInteger, Long> LUT = new HashMap <BigInteger, Long>();
    
    // DGK Private Key Constructor. ONLY variables, append LUT after
    public DGKPrivateKey(BigInteger P, BigInteger Q, BigInteger VP,
            BigInteger VQ, long U)
    {
    	   this(P, Q, VP, VQ, null, U);
    }

    // Original DGK Private Key Constructor
    public DGKPrivateKey (BigInteger P, BigInteger Q, BigInteger VP,
                          BigInteger VQ, HashMap <BigInteger, Long> lut, long U)
    {
        p = P;
        q = Q;
        vp = VP;
        vq = VQ;
        LUT = lut;
        u = U;
    }

    private void readObject(ObjectInputStream aInputStream)
            throws ClassNotFoundException,IOException
    {
        aInputStream.defaultReadObject();
    }

    private void writeObject(ObjectOutputStream aOutputStream) throws IOException
    {
        aOutputStream.defaultWriteObject();
    }
	
    // Get Methods
    public BigInteger getP() { return p; }
    public BigInteger getQ() { return q; }
    public BigInteger getVP() { return vp; }
    public BigInteger getVQ() { return vq; }
    public HashMap<BigInteger,Long> GetLUT() { return LUT; }
    public long GetU() { return u; }

    public void printKeys()
    {
        System.out.println("Private Key parameters...");
        System.out.println("P: " + p);
        System.out.println("Q: " + q);
        System.out.println("VP: " + vp);
        System.out.println("VQ: " + vq);
        System.out.println("U: " + u);
    }

    public void printLUT()
    {
		for (BigInteger k : LUT.keySet()) 
		{
			System.out.println(k + "," + LUT.get(k));
		}
    }
    
    public void generategLUT (DGKPublicKey pubKey)
    {
    	if(LUT != null)
    	{
    		return;
    	}
        BigInteger g = pubKey.g;
        BigInteger gvp = NTL.POSMOD(g,p).modPow(vp,p);
        // Build LUT
        for (int i = 0; i < u; ++i)
        {
            BigInteger decipher = gvp.modPow(NTL.POSMOD(BigInteger.valueOf((long) i),p),p);
            LUT.put(decipher, (long) i);
        }
    }

	public String getAlgorithm() 
	{
		return "DGK";
	}

	public String getFormat() 
	{
		return "NONE";
	}

	public byte[] getEncoded() 
	{
		return null;
	}
}