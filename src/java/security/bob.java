package java.security;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.Socket;

import security.DGK.DGKOperations;
import security.DGK.DGKPrivateKey;
import security.DGK.DGKPublicKey;
import security.DGK.NTL;
import security.paillier.PaillierCipher;
import security.paillier.PaillierPK;
import security.paillier.PaillierSK;

/**
Credits to Andrew Quijano and Dr. Samet Tonyali

Alice has [[x]] and [[y]]
Bob has the DGK and Paillier Public Keys

Terms of Use:
Feel free to use this code as you like.

DGK was created in 2007 by:
Ivan Damgard, Martin Geisler, and Mikkel Kroigaard (DGK).

Title of Papers: (Source of Protocol 1, Protocol 2)
Efficient and Secure Comparison for On-Line auctions (2007)
A correction to Efficient and Secure Comparison for Online auctions (2009)

Protocol 3 and Protocol 4 was created referencing Thjis Veugen's Paper:
Improving the DGK Comparison Protocol (2012)
*/

public class bob implements Runnable
{
	// Key Master
	protected Socket clientSocket = null;
	private PaillierPK pk = new PaillierPK();
	private PaillierSK sk = new PaillierSK(1024);
	
	private DGKPublicKey pubKey = null;
	private DGKPrivateKey privKey = null;
	
	//Input ObjectInputStream and Output ObjectOutputStream
	private ObjectOutputStream toAlice = null;
	private ObjectInputStream fromAlice = null;
	private boolean isDGK = false;

	public bob (Socket _clientSocket,
			PaillierPK _pk, PaillierSK _sk, DGKPublicKey _pubKey, DGKPrivateKey _privKey,
			boolean _isDGK)
	{
		this.clientSocket = _clientSocket;
		this.pk = _pk;
		this.sk = _sk;
		this.pubKey = _pubKey;
		this.privKey = _privKey;
		this.isDGK = _isDGK;
	}

	public void run()
	{
		System.out.println("INCOMING REQUEST FROM " + clientSocket.getInetAddress()+ "!!");
		try 
		{
			// Get I/O streams
			if(clientSocket != null)
			{
				toAlice = new ObjectOutputStream(clientSocket.getOutputStream());
				fromAlice = new ObjectInputStream(clientSocket.getInputStream());
			}

			/*
			 * To be used with either
			 * Finding max/min 
			 * or Sorting because we have no idea how many times
			 * Alice needs to call Protocol 2 to do this correctly.
			 */
			this.repeat_Protocol2();
			
			/*
			this.Protocol3(new BigInteger("60"));
			this.Protocol3(new BigInteger("60"));
			this.Protocol3(new BigInteger("60"));
			this.Protocol3(new BigInteger("60"));
			this.Protocol3(new BigInteger("60"));
			*/
			
			/*
			this.Protocol2();
			this.Protocol2();
			this.Protocol2();
			this.Protocol2();
			this.Protocol2();
			*/
			
			System.out.println("FINSIHED REQUEST!");
		} 
		catch (IOException e1) 
		{
			e1.printStackTrace();
		}
		catch (ClassNotFoundException e)
		{
			e.printStackTrace();
		}
	}
	
	/*
	 * Since Bob has the Public and Private Key
	 * Alice has the Array of encrypted values.
	 * By the end of this, Alice should have a 
	 * list of sorted encrypted values. 
	 */
	
	public void repeat_Protocol2()
			throws IOException, ClassNotFoundException
	{
		int counter = 0;
		while(fromAlice.readBoolean())
		{
			++counter;
			Protocol2();
		}
		System.out.println("Finishing up need for Protocol 2. Protocol was used " + counter + " times!");
	}
	
	private static int exponent(int base, int exponent)
	{
		int answer = 1;
		int counter = exponent;
		while (counter != 0)
		{
			answer*=base;
			--counter;
		}
		return answer;
	}
	
	private int Protocol2()
			throws IOException, ClassNotFoundException
	{
		//Step 1: Receive z from Alice
		//Get the input and output streams
		Object Obj;
		BigInteger result;
		BigInteger betaZZ;
		BigInteger z = null;
		BigInteger zDiv = null;

		BigInteger powL = BigInteger.valueOf(exponent(2, pubKey.l - 2));

		//Step 1: get [[z]] from Alice
		Obj = fromAlice.readObject();
		if (Obj instanceof BigInteger)
		{
			z = (BigInteger) Obj;
		}

		if(z != null)
		{
			if(isDGK)
			{
				z = BigInteger.valueOf(DGKOperations.decrypt(pubKey, privKey, z));
			}
			else
			{
				z = PaillierCipher.decrypt(z, sk);
			}

			//Step 2: compute Beta = z (mod 2^l),
			betaZZ = z.mod(powL);

			//Step 3: Alice computes r (mod 2^l) (Alpha)

			/*
			 * Step 4: Run Protocol 3
			 * x = alpha, y = beta
			 */
			Protocol3(betaZZ);

			//Step 5" Send [[z/2^l]], Alice has the solution from Protocol 3 already...
			if(isDGK)
			{
				zDiv = DGKOperations.encrypt(pubKey, z.divide(powL));
			}
			else
			{
				zDiv = PaillierCipher.encrypt(z.divide(powL), pk);
				//System.out.println("Z/2^l: " + Paillier.decrypt(zDiv, sk));
			}
		}

		toAlice.writeObject(zDiv);
		toAlice.flush();

		//Step 6 - 7: Alice Computes [[x <= y]]

		//Step 8 (UNOFFICIAL): Alice needs the answer...
		result = (BigInteger) fromAlice.readObject();
		if(isDGK)
		{
			result = BigInteger.valueOf(DGKOperations.decrypt(pubKey, privKey, result));
		}
		else
		{
			result = PaillierCipher.decrypt(result, sk);
		}
		toAlice.writeInt(result.intValue());
		toAlice.flush();

		// Bob has the answer as well for [[x <= y]]
		// Return the answer (method call)


		return result.intValue();
	}


	/*
	 * Alice has x, x is NOT encrypted!
	 * Bob has y, y is NOT encrypted!
	 * Bob has Public and Private Keys for DGK 
	 * 
	 * 
	 * Result: 
	 * Alice and Bob know the answer...
	 * 0 -> x <= y
	 * 1 -> x > y
	 */

	private int Protocol3(BigInteger y)
			throws IOException, ClassNotFoundException
	{
		Object x;
		BigInteger [] C = null;
		int deltaB = 0;
		BigInteger deltaA;
		int answer = -1;

		//Get the input and output streams

		//Step 1: Bob sends encrypted bits to Alice
		BigInteger EncY[] = new BigInteger[y.bitLength()];
		for (int i = 0; i < y.bitLength(); i++)
		{
			EncY[i] = DGKOperations.encrypt(pubKey, NTL.bit(y, i));
			//System.out.print(NTL.bit(y, i));
		}
		//System.out.println("");
		toAlice.writeObject(EncY);
		toAlice.flush();

		//Step 2: Wait for Alice to compute x XOR y

		//Step 3: Wait for Alice to compute set L and gamma A

		//Step 4: Wait for Alice to compute the array of C_i

		//Step 5: After blinding, Alice sends C_i to Bob

		/*
		 * Currently by design of the program
		 * 1- Alice KNOWS that bob will assume deltaB = 0.
		 *
		 * Alice knows the protocol should be skipped if
		 * the bit length is NOT equal.
		 *
		 * Case 1:
		 * y has more bits than x IMPLIES that y is bigger
		 * x <= y is 1 (true)
		 * given deltaB is 0 by default...
		 * deltaA must be 1
		 * answer = 1 XOR 0 = 1
		 *
		 * Case 2:
		 * x has more bits than x IMPLIES that x is bigger
		 * x <= y is 0 (false)
		 * given deltaB is 0 by default...
		 * deltaA must be 0
		 * answer = 0 XOR 0 = 0
		 */

		x = fromAlice.readObject();
		if (x instanceof BigInteger [])
		{
			C = (BigInteger []) x;
		}
		else if (x instanceof BigInteger)
		{
			deltaA = (BigInteger) x;

			// Case 1 delta B is 0
			// 1 XOR 0 = 0
			// x <= y -> 1 (true)
			if (deltaA.intValue() == 1)
			{
				answer = 1;
				return answer;
			}

			// Case 2, delta B is 0
			// 0 XOR 0 = 0
			// x <= y -> 0 (false)
			if (deltaA.intValue() == 0)
			{
				answer = 0;
				return answer;
			}
		}

		// Delta B is already set to 0!
		// Check for x = y as well!
		// Alice will send deltaA + sum(X xor Y) and Bob must decrypt it!

		if(C != null)
		{
			for (BigInteger C_i: C)
			{
				if (DGKOperations.decrypt(pubKey, privKey, C_i) == 0)
				{
					deltaB = 1;
					break;
				}
			}
		}

		// Step 7: Return Gamma B to Alice, Alice will compute GammaA XOR GammaB
		toAlice.writeInt(deltaB);
		toAlice.flush();

		// Step 8: Not part of Thjis...
		// FLAW: ANSWER IS COMING IN AS PLAIN TEXT!
		// Negotiate some key exchange?
		x = fromAlice.readObject();
		if (x instanceof BigInteger)
		{
			answer = ((BigInteger) x).intValue();
		}

		return answer;
	}
	
	public int Protocol4(BigInteger x, BigInteger y) 
			throws IOException, ClassNotFoundException
	{
		//Step 1: Receive z from Alice
		//Get the input and output streams
		Object Objz;
		BigInteger result = null;
		BigInteger z = null;
		BigInteger zDiv = null;

		int l = pubKey.l - 2;

		//Step 1: get [[z]] from Alice
		Objz = fromAlice.readObject();
		BigInteger EncZ = null;
		if (Objz instanceof BigInteger)
		{
			EncZ = (BigInteger) Objz;
		}

		if(isDGK)
		{
			z = BigInteger.valueOf(DGKOperations.decrypt(pubKey, privKey, EncZ));
		}
		else
		{
			z = PaillierCipher.decrypt(EncZ, sk);
		}

		//Step 2: compute Beta = z (mod 2^l), 
		int powL = exponent(2, l);
		BigInteger betaZZ = z.mod(BigInteger.valueOf(powL));

		//Step 3: Alice computes r (mod 2^l) (Alpha)

		// Step 4: Run Modified DGK Comparison Protocol
		// x = alpha, y = beta
		Protocol3(betaZZ, z);

		//Step 5" Send [[z/2^l]], Alice has the solution from Protocol 3 already...
		if(isDGK)
		{
			zDiv = DGKOperations.encrypt(pubKey, z.divide(BigInteger.valueOf(powL)));	
		}
		else
		{
			zDiv = PaillierCipher.encrypt(z.divide(BigInteger.valueOf(powL)), pk);
			System.out.println("Z/2^l: " + PaillierCipher.decrypt(zDiv, sk));	
		}

		toAlice.writeObject(zDiv);
		toAlice.flush();

		//Step 6 - 7: Alice Computes [[x <= y]]

		//Step 8 (UNOFFICIAL): Alice needs the answer...
		result = (BigInteger) fromAlice.readObject();
		if(isDGK)
		{
			result = BigInteger.valueOf(DGKOperations.decrypt(pubKey, privKey, result));
		}
		else
		{
			result = PaillierCipher.decrypt(result, sk);
		}
		toAlice.writeInt(result.intValue());
		toAlice.flush();

		// Bob has the answer as well for [[x <= y]]
		// Return the answer (method call)
		return result.intValue();
	}
	
	private int Protocol3(BigInteger beta, BigInteger z) 
			throws IOException, ClassNotFoundException
	{
		Object in;
		BigInteger [] C = null;
		BigInteger [] beta_bits = new BigInteger[beta.bitLength()];
		BigInteger d;
		int answer = -1;
		int deltaB = 0;
		BigInteger deltaA = new BigInteger("-1");
		
		// Step A: z < (N - 1)/2
		if(z.compareTo(pk.n.subtract(BigInteger.ONE).divide(new BigInteger("2")))==-1)
		{
			d = DGKOperations.encrypt(pubKey, BigInteger.ONE);
		}
		else
		{
			d = DGKOperations.encrypt(pubKey, BigInteger.ZERO);
		}
		toAlice.writeObject(d);
		
		// Step B: Send the encrypted Beta bits
		for (int i = 0; i < beta_bits.length;i++)
		{
			beta_bits[i] = DGKOperations.encrypt(pubKey, NTL.bit(beta, i));
		}
		toAlice.writeObject(beta_bits);
		
		// Step C: Alice corrects d...
		
		// Step D: Alice computes [[alpha XOR beta]]
		
		// Step E: Alice Computes alpha_hat and w_bits
		
		// Step F: Alice Exponentiates w_bits
		
		// Step G: Alice picks Delta A
		
		// Step H: Alice computes C_i
		
		// Step I: Alice blinds C_i
		
		// Step J: Get C_i and look for zeros
		in = fromAlice.readObject();
		if(in instanceof BigInteger[])
		{
			C = (BigInteger []) in;
		}
		else if (in instanceof BigInteger)
		{
			deltaA = (BigInteger) in;

			// Case 1 delta B is 0
			// 1 XOR 0 = 0
			// x <= y -> 1 (true)
			if (deltaA.intValue() == 1)
			{
				answer = 1;
				return answer;
			}

			// Case 2, delta B is 0
			// 0 XOR 0 = 0
			// x <= y -> 0 (false) 
			else if (deltaA.intValue() == 0)
			{
				answer = 0;
				return answer;
			}
		}
		
		for (int i = 0; i < C.length;i++)
		{
			if(DGKOperations.decrypt(pubKey, privKey, C[i])==0)
			{
				deltaB = 1;
				break;
			}
		}
		toAlice.writeInt(deltaB);
		
		// Extra step...Bob gets the answer from Alice
		answer = fromAlice.readInt();
		return answer;
	}
	
	public BigInteger division(int divisor) 
			throws ClassNotFoundException, IOException
	{
		BigInteger c = null;
		BigInteger z = null;
		Object alice = fromAlice.readObject();
		if(alice instanceof BigInteger)
		{
			z = (BigInteger) alice;
		}
		else
		{
			return new BigInteger("-1");
		}
		
		if(isDGK)
		{
			z = BigInteger.valueOf(DGKOperations.decrypt(pubKey, privKey, z));
		}
		else
		{
			z = PaillierCipher.decrypt(z, sk);
		}
		
		Protocol3(z.mod(BigInteger.valueOf(divisor)));
		
		c = z.divide(BigInteger.valueOf(divisor));
		if(isDGK)
		{
			toAlice.writeObject(DGKOperations.encrypt(pubKey, c));	
		}
		else
		{
			toAlice.writeObject(PaillierCipher.encrypt(c, pk));
		}
		
		// Get answer from Alice [[x/d]]
		alice = fromAlice.readObject();
		if (alice instanceof BigInteger)
		{
			return (BigInteger) alice;
		}
		else
		{
			return new BigInteger("-1");
		}
	}
}
