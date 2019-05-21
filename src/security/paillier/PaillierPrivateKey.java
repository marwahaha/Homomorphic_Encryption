package security.paillier;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.math.BigInteger;
import java.security.PrivateKey;

public class PaillierPrivateKey implements Serializable, PrivateKey
{
    // k1 is the security parameter. It is the number of bits in n.
    public int k1 = 1024;
    
    public PaillierPrivateKey(int n)
    {
        k1 = n;
    }

    public BigInteger n;
    public BigInteger modulus;
    
    public BigInteger lambda;
    public BigInteger mu;
    
    private static final long serialVersionUID = PrivateKey.serialVersionUID;

    private void readObject(ObjectInputStream aInputStream)
            throws ClassNotFoundException,IOException
    {
        aInputStream.defaultReadObject();
    }

    private void writeObject(ObjectOutputStream aOutputStream) throws IOException
    {
        aOutputStream.defaultWriteObject();
    }

	@Override
	public String getAlgorithm() 
	{
		return "Paillier";
	}

	@Override
	public String getFormat() 
	{
		return "NONE";
	}

	@Override
	public byte[] getEncoded() 
	{
		return null;
	}
}