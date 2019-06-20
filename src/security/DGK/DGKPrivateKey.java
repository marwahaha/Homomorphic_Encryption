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
    public final HashMap <BigInteger, Long> LUT = new HashMap<BigInteger, Long>();
    
    // Public key parameters
	final BigInteger n;
	final BigInteger g;
	final BigInteger h;
	final long u;
	final BigInteger bigU;
	
	// Key Parameters
	final int l;
	final int t;
	final int k;

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
    
    private void generategLUT()
    {
        BigInteger gvp = NTL.POSMOD(this.g, this.p).modPow(this.vp, this.p);
        for (int i = 0; i < this.u; ++i)
        {
            BigInteger decipher = gvp.modPow(NTL.POSMOD(BigInteger.valueOf((long) i), this.p), this.p);
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