package security.DGK;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.math.BigInteger;
import java.security.PublicKey;
import java.util.HashMap;

public class DGKPublicKey implements Serializable, PublicKey
{
	private static final long serialVersionUID = PublicKey.serialVersionUID;

	final BigInteger n;
	final BigInteger g;
	final BigInteger h;
	public final long u;
	public final BigInteger bigU;
	HashMap <Long, BigInteger> gLUT = null;
	HashMap <Long, BigInteger> hLUT = null;
	
	// Key Parameters
	public final int l;
	public final int t;
	public final int k;
	
	public DGKPublicKey(BigInteger N, BigInteger G, BigInteger H, long U, int L, int T, int K)
	{
		this(N, G, H, U, null, null, L, T, K);
	}
	
	//DGK Constructor with ALL parameters
	public DGKPublicKey(BigInteger n, BigInteger g, BigInteger h, long u,
						HashMap <Long,BigInteger> gLUT, HashMap<Long,BigInteger> hLUT, 
						int l, int t, int k)
	{
		this.n = n;
		this.g = g;
		this.h = h;
		this.u = u;
		this.bigU = BigInteger.valueOf(u);
		this.gLUT = gLUT;
		this.hLUT = hLUT;
		this.l = l; 
		this.t = t;
		this.k = k;
	}
	
	public void generatehLUT()
	{
		if(hLUT != null)
		{
			return;
		}
		else
		{
			this.hLUT = new HashMap<Long, BigInteger>();
		}
		
		for (int i = 0; i < 2*t; ++i)
		{
			//e = 2^i (mod n)
			//h^{2^i (mod n)} (mod n)
			//f(i) = h^{2^i}(mod n)
			BigInteger e = new BigInteger("2").modPow(BigInteger.valueOf((long)(i)), this.n);
			this.hLUT.put((long) i, this.h.modPow(e, this.n));
		}
	}
	
	public void generategLUT()
	{
		if(gLUT != null)
		{
			return;
		}
		else
		{
			this.gLUT = new HashMap<Long, BigInteger>();
		}
		
		for (int i = 0; i < this.u; ++i)
		{
			BigInteger out = this.g.modPow(BigInteger.valueOf((long)i), this.n);
			this.gLUT.put((long) i, out);
		}
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

	public void printhLUT()
	{
		for (long k : hLUT.keySet()) 
		{
		   System.out.println(k + "," + hLUT.get(k));
		}
	}
	
	public void printgLUT()
	{
		for (long k : gLUT.keySet())
		{
			System.out.println(k + "," + gLUT.get(k));
		}
	}
	
	public BigInteger ZERO()
	{
		return DGKOperations.encrypt(this, 0);
	}
	
	public BigInteger ONE()
	{
		return DGKOperations.encrypt(this, 1);
	}

	public String getAlgorithm() 
	{
		return null;
	}

	public String getFormat() 
	{
		return null;
	}

	public byte[] getEncoded() 
	{
		return null;
	}
	
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
}