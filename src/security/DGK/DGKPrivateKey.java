package security.DGK;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.util.HashMap;

public class DGKPrivateKey implements Serializable, PrivateKey
{
    private static final long serialVersionUID = PrivateKey.serialVersionUID;

    // Private Key Parameters
    final BigInteger p;
    private final BigInteger q;
    final BigInteger vp;
    private final BigInteger vq;
    private HashMap <BigInteger, Long> LUT;
    
    // Public key parameters
	public final BigInteger n;
	public final BigInteger g;
	public final BigInteger h;
	public final long u;
	public final BigInteger bigU;
	public HashMap <Long, BigInteger> gLUT = null;
	public HashMap <Long, BigInteger> hLUT = null;
	
	// Key Parameters
	public final int l;
	public final int t;
	public final int k;

    // Original DGK Private Key Constructor
    public DGKPrivateKey (BigInteger p, BigInteger q, BigInteger vp,
                          BigInteger vq, DGKPublicKey pubKey)
    {
    	// Fill Private Key Parameters
    	this.p = p;
        this.q = q;
        this.vp = vp;
        this.vq = vq;
        
        // Public Key Parameters
    	this.n = pubKey.n;
    	this.g = pubKey.g;
    	this.h = pubKey.h;
        this.u = pubKey.u;
    	this.bigU = pubKey.bigU;
    	this.gLUT = pubKey.gLUT;
    	this.hLUT = pubKey.hLUT;
    	
    	// Key Parameters
    	this.l = pubKey.l;
    	this.t = pubKey.t;
    	this.k = pubKey.k;
    	
    	// Now that I have public key paramaters, build LUT!
    	this.generategLUT();
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
    
    public HashMap<BigInteger,Long> GetLUT() 
    { 
    	return LUT; 
    }
    
    private void generategLUT()
    {
    	this.LUT = new HashMap<BigInteger, Long>();
    	
        BigInteger gvp = NTL.POSMOD(g, p).modPow(vp, p);
        // Build LUT
        for (int i = 0; i < u; ++i)
        {
            BigInteger decipher = gvp.modPow(NTL.POSMOD(BigInteger.valueOf((long) i), p), p);
            this.LUT.put(decipher, (long) i);
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
	
	// Not going to print private key parameters...
    public String toString()
    {
    	String answer = "";
    	answer += "n: " + n + ", " + '\n';
    	answer += "g: " + g + ", " + '\n';
    	answer += "h: " + h + ", " + '\n';
    	answer += "u: " + bigU + ", " + '\n';
    	answer += "l: " + l + ", " + '\n';
    	answer += "t: " + t + ", " + '\n';
    	answer += "k: " + k + ", " + '\n';
    	return answer;
    }

	public BigInteger getVq() 
	{
		return vq;
	}

	public BigInteger getQ()
	{
		return q;
	}
}