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

	public BigInteger n;
	public BigInteger g;
	public BigInteger h;
	public long u;
	public BigInteger bigU = null;
	public int l;
	public int t;
	public int k;
	public HashMap <Long, BigInteger> gLUT = null;
	public HashMap <Long, BigInteger> hLUT = null;
		
	public DGKPublicKey(BigInteger N, BigInteger G, BigInteger H, long U, int L, int T, int K)
	{
		this(N, G, H, U, null, null, L, T, K);
	}
	
	//DGK Constructor with ALL parameters
	public DGKPublicKey(BigInteger N, BigInteger G, BigInteger H, long U,
						HashMap <Long,BigInteger> GLUT, HashMap<Long,BigInteger> HLUT, int L, int T, int K)
	{
		n = N;
		g = G;
		h = H;
		u = U;
		bigU = BigInteger.valueOf(u);
		gLUT = GLUT;
		hLUT = HLUT;
		l = L; 
		t = T;
		k = K;
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
			BigInteger e = new BigInteger("2").modPow(BigInteger.valueOf((long)(i)),n);
			BigInteger out = h.modPow(e,n);
			this.hLUT.put((long) i, out);
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
		
		for (int i = 0; i < u; ++i)
		{
			BigInteger out = g.modPow(BigInteger.valueOf((long)i), n);
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

	public void printKeys()
	{
		System.out.println("Printing Public Key parameters...");
		System.out.println("Parameters: "  + " t: " + t + " l: " + l + " k: " + k);
		System.out.println("N: " + n);
		System.out.println("G: " + g);
		System.out.println("H: " + h);
		System.out.println("U: " + u);
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
    	answer += "n: " + n + ", ";
    	answer += "g: " + g + ", ";
    	answer += "h: " + h + ", ";
    	answer += "u: " + bigU + ", ";
    	answer += "l: " + l + ", ";
    	answer += "t: " + t + ", ";
    	answer += "k: " + k + ", ";
    	return answer;
    }
}