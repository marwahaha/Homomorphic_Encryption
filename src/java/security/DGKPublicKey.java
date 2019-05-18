package java.security;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.math.BigInteger;
import java.util.HashMap;

public class DGKPublicKey implements Serializable, PublicKey
{
	private static final long serialVersionUID = PublicKey.serialVersionUID;

	public BigInteger n;
	public BigInteger g;
	public BigInteger h;
	public long u;
	public BigInteger bigU;
	public int l;
	public int t;
	public int k;
	//public BigInteger u;
	public HashMap <Long, BigInteger> gLUT = new HashMap <Long, BigInteger> ();
	public HashMap <Long, BigInteger> hLUT = new HashMap <Long, BigInteger> ();
		
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
			hLUT = new HashMap<Long, BigInteger>();
		}
		
		for (int i = 0; i < 2*t; ++i)
		{
			BigInteger e = new BigInteger("2").modPow(BigInteger.valueOf((long)(i)),n);
			//e = 2^i (mod n)
			BigInteger out = h.modPow(e,n);
			//h^{2^i (mod n)} (mod n)
			hLUT.put((long)i,out);
			//f(i) = h^{2^i}(mod n)
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
			gLUT = new HashMap<Long, BigInteger>();
		}
		
		for (int i = 0; i < u; ++i)
		{
			BigInteger out = g.modPow(BigInteger.valueOf((long)i), n);
			gLUT.put((long) i, out);
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
}