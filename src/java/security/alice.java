package java.security;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.Socket;
import java.util.ArrayList;
import java.util.Random;

import java.util.Deque;
import java.util.Iterator;
import java.util.LinkedList;

/**
Credits to Andrew Quijano and Dr. Samet Tonyali
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

enum Algorithm
{
    INSERT_SORT, MERGE_SORT, QUICK_SORT;
}

public class alice implements Runnable
{
	class Pair 
	{
		BigInteger min;
		BigInteger max;
	}
	
	private final static int BILLION = 1000000000;
	private Random rnd = new Random();
	
	// Alice will be given the Public Keys
	private PaillierPK pk = null;
	private DGKPublicKey pubKey = null;
	
	// Needed for comparison
	private boolean isDGK = false;
	public ArrayList<BigInteger> toSort = new ArrayList<BigInteger>();
	public BigInteger [] sortedArray;
	
	//Socket Communication
	private Socket clientSocket = null;
	private ObjectOutputStream toBob = null;
	private ObjectInputStream fromBob = null;
	
	// Current Algorithm to Sort with...
	private Algorithm algo;
	
	public alice (Socket _clientSocket,
			PaillierPK _pk, DGKPublicKey _pubKey,
            boolean _isDGK, ArrayList<BigInteger> _toSort)
	{
		 this.clientSocket = _clientSocket;
		 this.pk = _pk;
		 this.pubKey = _pubKey;
		 this.isDGK = _isDGK;
		 this.toSort = _toSort;
		 this.algo = Algorithm.valueOf("QUICK_SORT");
	}

	public alice (ObjectInputStream _fromBob, ObjectOutputStream _toBob,
			PaillierPK _pk, DGKPublicKey _pubKey,
			boolean _isDGK, ArrayList<BigInteger> _toSort)
	{
		this.fromBob = _fromBob;
		this.toBob = _toBob;
		this.pk = _pk;
		this.pubKey = _pubKey;
		this.isDGK = _isDGK;
		this.toSort = _toSort;
		this.algo = Algorithm.valueOf("QUICK_SORT");
	}
	
	@Override
	public void run()
	{
		try
		{
			if(clientSocket != null)
			{	
				System.out.println("INCOMING REQUEST FROM " + clientSocket.getInetAddress()+ "!!");
				toBob = new ObjectOutputStream(clientSocket.getOutputStream());
				fromBob = new ObjectInputStream(clientSocket.getInputStream());				
			}
			long start = System.nanoTime();
			//this.findMinIDX(toSort, true);
			this.sortArray();
			
			/*
			// Test out Division!
			BigInteger answer;
			if(isDGK)
			{
				answer = this.division(DGKOperations.encrypt(pubKey, 50), 2);
				System.out.println("answer: " + DGKOperations.decrypt(pubKey, server.privKey, answer));
				
				answer = this.division(DGKOperations.encrypt(pubKey, 100), 2);
				System.out.println("answer: " + DGKOperations.decrypt(pubKey, server.privKey, answer));
				
				answer = this.division(DGKOperations.encrypt(pubKey, 25), 3);
				System.out.println("answer: " + DGKOperations.decrypt(pubKey, server.privKey, answer));
			
			}
			else
			{	
				answer = this.division(Paillier.encrypt(new BigInteger("60"), pk), 2);
				System.out.println("answer: " + Paillier.decrypt(answer, server.sk));
				
				answer = this.division(Paillier.encrypt(new BigInteger("30"), pk), 2);
				System.out.println("answer: " + Paillier.decrypt(answer, server.sk));
				
				answer = this.division(Paillier.encrypt(new BigInteger("30"), pk), 3);
				System.out.println("answer: " + Paillier.decrypt(answer, server.sk));
			}
			*/
					
			System.out.println("SORTING REQUEST FINISHED IN " + ((System.nanoTime() - start)/BILLION) + " Seconds");
			// this.closeThread();
		}
		catch (IOException | ClassNotFoundException e)
		{
			e.printStackTrace();
		} 
		catch (InterruptedException e) 
		{
			e.printStackTrace();
		}
	}
	
	public void setDGKstatus(boolean _isDGK)
	{
		isDGK = _isDGK;
	}
	
	public void setSorting(ArrayList<BigInteger> _toSort)
	{
		toSort = _toSort;
	}
	
	public void sendRequest() throws IOException
	{
		toBob.writeBoolean(true);
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

	private static int log2(int value)
	{
		return (int) (Math.log10((double) value)/Math.log(2.0));
	}

	public int Protocol2(BigInteger x, BigInteger y) 
			throws IOException, ClassNotFoundException
	{
		int protocolThree = -1;
		int comparison = -1;
		BigInteger z = null;
		BigInteger zdiv2L =  null;
		BigInteger result = null;
		Object bob = null;

		BigInteger powL = BigInteger.valueOf(exponent(2,pubKey.l - 2));//2^l
		//System.out.println("2^l: "+ powL);

		//  Step 1: 0 <= r < N
		BigInteger r = NTL.RandomBnd(pubKey.u);
		//System.out.println("r: " + bigR);

		/*
		 * Step 2: Alice computes [[z]] = [[x - y + 2^l + r]]
		 * Send Z to Bob
		 */
		if (isDGK)
		{
			z = DGKOperations.DGKAdd(pubKey, x, DGKOperations.encrypt(pubKey, r.add(powL)));//[[x + 2^l + r]]
			//System.out.println("z + 2^l + x: " + Paillier.decrypt(z, sk));
			z = DGKOperations.DGKSubtract(pubKey, z, y);//[[z]] = [[x - y + 2^l + r]]
			//System.out.println("value of Z: " + Paillier.decrypt(z, sk));
		}
		else
		{
			z = Paillier.add(x, Paillier.encrypt(r.add(powL), pk), pk);// = [[x + 2^l + r]]
            z = Paillier.subtract(z, y, pk);
            //[[z]] = [[x + 2^l + r - y]]
			//Systesm.out.println("value of Z: " + Paillier.decrypt(z, sk));
		}
		toBob.writeObject(z);
		toBob.flush();
		
		// Step 2: Bob decrypts[[z]] and computes beta = z (mod 2^l)

		// Step 3: alpha = r (mod 2^l)
		BigInteger alphaZZ = NTL.POSMOD(r, powL);
		//System.err.println("alpha: " + alphaZZ + " beta: " + Paillier.decrypt(z, sk).mod(powL));

		// Step 4: Complete Protocol 1 or Protocol 3
        int deltaA = rnd.nextInt(2);
		int deltaB;
        protocolThree = Protocol3(alphaZZ, deltaA);
		
        /*
		 * BE CAREFUL DO NOT USE THE DIRECT ANSWER FROM PROTOCOL 3
		 *
		 * deltaA XOR deltaB = protocolThree
		 * deltaA XOR protocolThree = deltaB
		 */
		if(deltaA == protocolThree)
        {
            deltaB = 0;
        }
        else
        {
            deltaB = 1;
        }
		
		// Step 5: Bob sends z/2^l and GammaB 
		bob = fromBob.readObject();
		if (bob instanceof BigInteger)
		{
			zdiv2L = (BigInteger) bob;
		}
		else
		{
			System.err.println("Invalid object: " + bob.getClass());
		}

		/*
		 * Step 6
		 * Alice Computes GammaA XOR GammaB
		 * to finish Protocol 3
		 * 
		 * My modifications:
		 * This is taken care of in step 7 where
		 * I just encrpyt the answer from Protocol 3...
		 */

		/*
		 * Step 7, Alice Computes [[x <= y]]
		 * = [[x <= y]]
		 * = [[z/2^l]] * ([[r/2^l]] [[alpha < Beta]])^-1 
		 * = [[z/2^l - r/2^l - (alpha <= beta)]]
		 */

		if(isDGK)
		{
			result = DGKOperations.DGKSubtract(pubKey, zdiv2L, DGKOperations.encrypt(pubKey, r.divide(powL)));
			result = DGKOperations.DGKSubtract(pubKey, result, DGKOperations.encrypt(pubKey, protocolThree));
		}
		else
		{
		    // = [[z/2^l]] * [[r/2^l]]^{-1} = [[z/2^l - r/2^l]]
            if(zdiv2L != null)
            {
                result = Paillier.subtract(zdiv2L, Paillier.encrypt(r.divide(powL), pk), pk);
            }
            if(result != null)
            {
                // = [[z/2^l - r/2^l - (alpha <= beta)]]
                if(deltaA == 1)
                {
                    result = Paillier.subtract(result, Paillier.encrypt(deltaB, pk), pk);
                }
                else
                {
                    result = Paillier.subtract(result, Paillier.encrypt((1 - deltaB), pk), pk);
                }
            }
		}

		/*
		 * Unofficial Step 8:
		 * Since the result is encrypted...I need to send
		 * this back to Bob (Android Phone) to decrypt the solution...
		 * 
		 * Bob by definition would know the answer as well.
		 */

		toBob.writeObject(result);
		comparison = fromBob.readInt();// x <= y
		return comparison;
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

	private int Protocol3(BigInteger x, int deltaA)
			throws ClassNotFoundException, IOException
	{
		BigInteger [] EncY;
		int deltaB;
		int answer;
		Object obj;

		//Step 1: Receive y_i bits from Bob
		obj = fromBob.readObject();
		if (obj instanceof BigInteger[])
		{
			EncY = (BigInteger []) obj;
		}
		else
		{
			System.err.println("Error: " + obj.getClass());
			return -1;
		}
		int yBits = EncY.length;
		//System.out.println("size of EncY: " + max);

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

		// Case 1, delta B is ALWAYS INITIALIZED TO 0
		// y has more bits -> y is bigger
		if (x.bitLength() < yBits)
		{
			toBob.writeObject(new BigInteger("1"));
			toBob.flush();
			// x <= y -> 1 (true)
			return 1;
		}

		// Case 2 delta B is 0
		// x has more bits -> x is bigger
		else if(x.bitLength() > yBits)
		{
			toBob.writeObject(new BigInteger("0"));
			toBob.flush();
			// x <= y -> 0 (false)
			return 0;
		}

		// if equal bits, proceed!

		//Step 2: compute Encrypted X XOR Y
		BigInteger [] XOR = new BigInteger[yBits];
		for (int i = 0; i < yBits; i++)
		{
			//Enc[x XOR y] = [y_i]
			if (NTL.bit(x, i) == 0)
			{
				XOR[i] = EncY[i];
			}
			//Enc[x XOR y] = [1] - [y_i]
			else
			{
				XOR[i] = DGKOperations.DGKSubtract(pubKey, DGKOperations.encrypt(pubKey, 1), EncY[i]);
			}
			//System.out.print(DGKOperations.decrypt(pubKey, privKey, encXORY[i]));
		}
		//System.out.println("");

		/*
		 * Step 3A: Select gamma A and set up C_i
		 * Protocol 3 only works if GammaA = 1, in ALL cases.
		 * Protocol 3 doesn't work if x = y and GammaA = 0
		 */

		// THIS STEP IS ALREADY DONE AT THE START!!!
		// System.out.println("Gamma A is: " + GammaA);

		// Step 3B: Collect index of all index where x_i = GammaA
		ArrayList <Integer> ListofGammaA = new ArrayList<>();
		for (int i=0;i < yBits;i++)
		{
			if (NTL.bit(x, i) == deltaA)
			{
				ListofGammaA.add(i);
			}
		}

		//Step 4A: Generate C_i, see c_{-1} to test for equality!
		//C_{-1} = C_i[yBits], will be computed at the end...
		BigInteger [] C_i = new BigInteger [yBits + 1];
		BigInteger product = DGKOperations.encrypt(pubKey, 0);

		//System.out.println("new C_i");
		for (int i = 0; i < yBits; i++)
		{
			// Goes from yBits - 1 to 0
			C_i [yBits-1-i] = product;
			product = DGKOperations.DGKAdd(pubKey, product, XOR[i]);
			//System.out.print(DGKOperations.decrypt(pubKey, privKey,C_i[max-1-i]));
		}

		/*
		 * Step 4B: alter C_i using Gamma A
		 * Also compute:
		 * [1] - [y_i bit]
		 */
		//System.out.println("");
		//System.out.println("1 - y_i:");
		BigInteger [] minus = new BigInteger[yBits];

		for(int i = 0; i < yBits; i++)
		{
			minus [i] = DGKOperations.DGKSubtract(pubKey, DGKOperations.encrypt(pubKey,1), EncY[i]);
			//System.out.print(DGKOperations.decrypt(pubKey, privKey, minus[i]));
		}

		for (int i = 0; i < yBits; i++)
		{
			if (deltaA==0)
			{
				// Step 4 = [1] - [y_i bit] + [c_i]
				C_i[i]= DGKOperations.DGKAdd(pubKey,C_i[i], minus[yBits-1-i]);
			}
			else
			{
				// Step 4 = [y_i] + [c_i]
				C_i[i]= DGKOperations.DGKAdd(pubKey, C_i[i], EncY[yBits-1-i]);
			}
		}

		/*
		System.out.println("");
		System.out.println("Updated C_i");
		for (int i = 0; i < max; i++)
		{
			System.out.print(DGKOperations.decrypt(pubKey, privKey, C_i[max-1-i]));
		}
		System.out.println("");
	    */

		//Step 5: Apply the Blinding to C_i and send it to Bob
		for (int i = 0; i < yBits;i++)
		{
			// if i is NOT in L, just place a random NON-ZERO
			if(!ListofGammaA.contains(i))
			{
				// System.out.println("NOT in L: " + i);
				// Should be random numbers! Just used 7 for debugging purposes!
				C_i[yBits-1-i] = DGKOperations.encrypt(pubKey, 7);
			}

			// if i is IN L, raise by some exponent r_i of 2t bits...
			// Note Bob will look for 0, which will determine the answer!
            /*
			else
			{

			}
			*/
		}

		/*
        System.out.println("Updated C_i with blinding...");
        for (int i = 0; i < yBits;i++)
		{
			System.out.print(DGKOperations.decrypt(pubKey, privKey, C_i[max-1-i]));
		}
		System.out.println("");
		*/

		//This is your c_{-1}
		C_i[yBits] = DGKOperations.DGKSum(pubKey, XOR);	//This is your c_{-1}
		C_i[yBits] = DGKOperations.DGKAdd(pubKey, C_i[yBits], DGKOperations.encrypt(pubKey,deltaA));

		//Send to Bob, C_i and sum of XOR (equality check)
		toBob.writeObject(C_i);
		toBob.flush();

		/*
		 * Step 7: Obtain GammaB from Bob
		 * GammaA XOR GammaB = 0 or 1.
		 * Now I am not sure if GammaB should be encrypted or not?
		 */

		// Get GammaB from Bob
		// Security not compromised
		// because deltaA is secret from Bob
		// and random!
		deltaB = fromBob.readInt();

		// 1 XOR 1 = 0 and 0 XOR 0 = 0, so X > Y
		if (deltaA == deltaB)
		{
			answer = 0;
		}
		// 1 XOR 0 = 1 and 0 XOR 1 = 1, so X <= Y
		else
		{
			answer = 1;
		}

		/*
		 * Step 8: Bob has the Private key anyways...
		 * Send him the encrypted answer!
		 * Alice and Bob know now without revealing x or y!
		 */
		toBob.writeObject(BigInteger.valueOf(answer));
		toBob.flush();
		return answer;
	}

	public int Protocol4(BigInteger x, BigInteger y) 
			throws IOException, ClassNotFoundException
	{
		int protocolThree = -1;
		int comparison = -1;
		BigInteger z = null;
		BigInteger zdiv2L =  null;
		BigInteger result = null;
		Object bob = null;

		BigInteger powL = BigInteger.valueOf(exponent(2,pubKey.l - 2));//2^l
		//System.out.println("2^l: "+ powL);

		//  Step 1: 0 <= r < N
		BigInteger bigR = NTL.RandomBnd(pubKey.u);
		//System.out.println("r: " + bigR);

		/*
		 * Step 2: Alice computes [[z]] = [[x - y + 2^l + r]]
		 * Send Z to Bob
		 */
		if (isDGK)
		{
			BigInteger xminusy = DGKOperations.DGKSubtract(pubKey, x, y);//[[x - y]]
			//System.out.println("x - y: " + Paillier.decrypt(xminusy, sk));

			BigInteger newData = DGKOperations.encrypt(pubKey, bigR.add(powL));//[[2^l + r]]
			//System.out.println("z + 2^l: " + Paillier.decrypt(newData, sk));

			z = DGKOperations.DGKSubtract(pubKey, xminusy, newData);//[[z]] = [[x - y + 2^l + r]]
			//System.out.println("value of Z: " + Paillier.decrypt(z, sk));
		}
		else
		{			
			BigInteger xminusy = Paillier.subtract(x, y, pk);//[[x - y]]
			//System.out.println("x - y: " + Paillier.decrypt(xminusy, sk));

			BigInteger newData = Paillier.encrypt(bigR.add(powL), pk);//[[2^l + r]]
			//System.out.println("z + 2^l: " + Paillier.decrypt(newData, sk));

			z = Paillier.add(xminusy, newData, pk);//[[z]] = [[x - y + 2^l + r]]
			//Systesm.out.println("value of Z: " + Paillier.decrypt(z, sk));
		}
		toBob.writeObject(z);
		toBob.flush();
		
		// Step 2: Bob decrypts[[z]] and computes beta = z (mod 2^l)

		// Step 3: alpha = r (mod 2^l)
		BigInteger alphaZZ = NTL.POSMOD(bigR, powL);
		//System.err.println("alpha: " + alphaZZ + " beta: " + Paillier.decrypt(z, sk).mod(powL));

		// Step 4: See Modified Comparison Protocol
		protocolThree = Protocol3(alphaZZ, z);
		
		// Step 5: Bob sends z/2^l and GammaB 
		bob = fromBob.readObject();
		if (bob instanceof BigInteger)
		{
			zdiv2L = (BigInteger) bob;
		}
		else
		{
			System.err.println("Invalid object: " + bob.getClass());
		}

		/*
		 * Step 6
		 * Alice Computes GammaA XOR GammaB
		 * to finish Protocol 3
		 * 
		 * My modifications:
		 * This is taken care of in step 7 where
		 * I just encrpyt the answer from Protocol 3...
		 */

		/*
		 * Step 7, Alice Computes [[x <= y]]
		 * = [[x <= y]]
		 * = [[z/2^l]] * ([[r/2^l]] [[alpha < Beta]])^-1 
		 * = [[z/2^l - r/2^l - (alpha <= beta)]]
		 */

		if(isDGK)
		{
			BigInteger rdiv2L = DGKOperations.encrypt(pubKey, bigR.divide(powL));
			result = DGKOperations.DGKSubtract(pubKey, zdiv2L, rdiv2L);
			result = DGKOperations.DGKSubtract(pubKey, result, DGKOperations.encrypt(pubKey, protocolThree));
		}
		else
		{			
			// = [[r/2^l]]
			//System.out.println("(z - r)/2^l= (x - y)/2^l: " + (Paillier.decrypt(z, sk).subtract(bigR)).divide(powL));
			BigInteger rdiv2L = Paillier.encrypt(bigR.divide(powL), pk);

			// = [[z/2^l]] * [[r/2^l]]^{-1} = [[z/2^l - r/2^l]]
			//System.out.println("z/2^l: " + Paillier.decrypt(zdiv2L, sk));
			//System.out.println("r/2^l: "+ Paillier.decrypt(rdiv2L, sk));
			result = Paillier.subtract(zdiv2L, rdiv2L, pk);

			//Should expect a 0 or 1.
			//System.out.println("[[z/2^l - r/2^l]]: " + Paillier.decrypt(result, sk));			

			// = [[z/2^l - r/2^l - (alpha <= beta)]]
			result = Paillier.subtract(result, Paillier.encrypt(protocolThree, pk), pk);
			//System.out.println("[[z/2^l - r/2^l - (a <= b)]]: " + Paillier.decrypt(result, sk));	
		}

		/*
		 * Unofficial Step 8:
		 * Since the result is encrypted...I need to send
		 * this back to Bob (Android Phone) to decrypt the solution...
		 * 
		 * Bob by definition would know the answer as well.
		 */

		toBob.writeObject(result);
		comparison = fromBob.readInt();// x <= y
		return comparison;
	}
	
	private int Protocol3(BigInteger alpha, BigInteger r) 
			throws ClassNotFoundException, IOException
	{
		Object in;
		BigInteger [] beta_bits = null;
		BigInteger [] encAlphaXORBeta = null;
		BigInteger [] w = null;
		BigInteger [] c = null;
		BigInteger alpha_hat = null;
		BigInteger d = null;
		
		// Step A: get d from Bob
		in = fromBob.readObject();
		if (in instanceof BigInteger)
		{
			d = (BigInteger) in;
		}
		
		// Step B: get beta_bits from Bob
		in = fromBob.readObject();
		if (in instanceof BigInteger[])
		{
			beta_bits = (BigInteger []) in;
		}
		
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

		// Case 1, delta B is ALWAYS INITIALIZED TO 0
		// y has more bits -> y is bigger
		if (alpha.bitLength() < beta_bits.length)
		{
			toBob.writeObject(new BigInteger("1"));
			toBob.flush();
			// x <= y -> 1 (true)
			return 1;
		}

		// Case 2 delta B is 0
		// x has more bits -> x is bigger
		else if(alpha.bitLength() > beta_bits.length)
		{
			toBob.writeObject(new BigInteger("0"));
			toBob.flush();
			// x <= y -> 0 (false)
			return 0;
		}
		
		// Step C: Alice corrects d...
		// r < (N - 1)/2
		if(r.compareTo(pk.n.subtract(BigInteger.ONE).divide(new BigInteger("2")))==-1)
		{
			d = DGKOperations.encrypt(pubKey, BigInteger.ZERO);
		}
		
		// Step D: Compute alpha_bits XOR beta_bits
		encAlphaXORBeta = new BigInteger[beta_bits.length];
		for (int i = 0; i < encAlphaXORBeta.length; i++)
		{
			//Enc[x XOR y] = [y_i]
			if (NTL.bit(alpha, i) == 0)
			{
				encAlphaXORBeta[i] = beta_bits[i];
			}
			//Enc[x XOR y] = [1] - [y_i]
			else
			{
				encAlphaXORBeta[i] = DGKOperations.DGKSubtract(pubKey, DGKOperations.encrypt(pubKey, 1), beta_bits[i]);				
			}
			//System.out.print(DGKOperations.decrypt(pubKey, privKey, encXORY[i]));
		}
		
		// Step E: Compute Alpha Hat
		alpha_hat = r.subtract(pk.n).mod(BigInteger.valueOf(exponent(2, pubKey.l - 2)));
		w = new BigInteger[beta_bits.length];
		
		for (int i = 0; i < beta_bits.length;i++)
		{
			if(NTL.bit(alpha_hat, i) == NTL.bit(alpha, i))
			{
				w[i] = encAlphaXORBeta[i];
			}
			else
			{
				w[i] = DGKOperations.DGKSubtract(pubKey, encAlphaXORBeta[i], d);
			}
		}
		
		// Step F: 
		for (int i = 0; i < beta_bits.length;i++)
		{
			BigInteger product = DGKOperations.encrypt(pubKey, BigInteger.ZERO);
			w[i] = DGKOperations.DGKMultiply(pubKey, w[i], exponent(2, i));
		}
		
		// Step G:
		int deltaA = rnd.nextInt(2);
		int s = 1 - (2 * deltaA);
		BigInteger S = DGKOperations.encrypt(pubKey, s);
		
		// Step H:
		c = new BigInteger[beta_bits.length];
		for (int i = 0; i < beta_bits.length;i++)
		{
			// Get Exponent
			c[i] = DGKOperations.DGKAdd(pubKey, S, DGKOperations.encrypt(pubKey, NTL.bit(alpha, i)));
		}
		
		// Step I: BLIND THE EXPONENTS
		for (int i = 0; i < beta_bits.length;i++)
		{
			c[i] = DGKOperations.DGKMultiply(pubKey, c[i], 1);
		}
		
		// Step J: Bob checks whether a C_i has a zero or not...get delta B.
		int deltaB = fromBob.readInt();
		
		int answer = -1;
		// 1 XOR 1 = 0 and 0 XOR 0 = 0, so X > Y
		if (deltaA == deltaB)
		{
			answer = 0;
		}
		// 1 XOR 0 = 1 and 0 XOR 1 = 1, so X <= Y
		else
		{
			answer = 1;
		}
		toBob.writeInt(answer);
		return answer;
	}
	
	/*
	 * See Protocol 2:
	 * Encrypted Integer Division by
	 * Thjis Veugen
	 */
	
	public BigInteger division(BigInteger x, int d) 
			throws IOException, ClassNotFoundException
	{
		Object in;
		BigInteger answer;
		BigInteger c = null;
		BigInteger z;
		BigInteger r;
		
		if(isDGK)
		{
			r = NTL.RandomBnd(log2((int) (pubKey.u - 1)/2));
			z = DGKOperations.DGKAdd(pubKey, x, DGKOperations.encrypt(pubKey, r));
		}
		else
		{
			r = NTL.RandomBnd(pk.n.subtract(BigInteger.ONE).divide(new BigInteger("2")));
			z = Paillier.add(x, Paillier.encrypt(r, pk), pk);
		}
		toBob.writeObject(z);
		toBob.flush();
		
		int t = Protocol3(r.mod(BigInteger.valueOf(d)), rnd.nextInt(2));
		System.out.println("(Division) Protocol 3 answer is: " + t);
		
		in = fromBob.readObject();
		if (in instanceof BigInteger)
		{
			c = (BigInteger) in;
		}
		
		/*
		 * The Protocol works...
		 * But for some odd reason it is always 1 off...
		 */
		if (isDGK)
		{
			// [[z/d - r/d]]
			answer = DGKOperations.DGKSubtract(pubKey, c, DGKOperations.encrypt(pubKey, r.divide(BigInteger.valueOf(d))));
			
			// [[z/d - r/d - t]]
			answer = DGKOperations.DGKSubtract(pubKey, answer, DGKOperations.encrypt(pubKey, t));
			
			// DO NOT USE BELOW
			//answer = DGKOperations.DGKAdd(pubKey, answer, DGKOperations.encrypt(pubKey, t));
			
			answer = DGKOperations.DGKAdd(pubKey, answer, DGKOperations.encrypt(pubKey, 1));
		}
		else
		{
			// [[z/d - r/d]]
			answer = Paillier.subtract(c, Paillier.encrypt(r.divide(BigInteger.valueOf(d)), pk), pk);
			
			// [[z/d - r/d - t]]
			answer = Paillier.subtract(answer, Paillier.encrypt(BigInteger.valueOf(t), pk), pk);
			
			// DO NOT USE BELOW
			//answer = Paillier.add(answer, Paillier.encrypt(BigInteger.valueOf(t), pk), pk);
			
			answer = Paillier.add(answer, Paillier.encrypt(BigInteger.ONE, pk), pk);
		}
		toBob.writeObject(answer);
		return answer;
	}

	/*
	 * Purpose of Method: 
	 * Input:
	 * An Array list of Encrypted Paillier Values and Socket to Bob (KeyMaster)
	 * 
	 * What it does:
	 * It will find the index of the smallest encrypted value.
	 * This is to avoid having to consistently make deep copies/keep track of index...
	 * It will be assumed Alice can build a new sorted array list with the index.
	 * 
	 * This will use Protocol 2/Protocol 3
	 */
	
	public BigInteger getMin(ArrayList<BigInteger> input) 
			throws ClassNotFoundException, IOException
	{
		return findExtrema(input, true).min;
	}
	
	public BigInteger getMax(ArrayList<BigInteger> input) 
			throws ClassNotFoundException, IOException
	{
		return findExtrema(input, true).max;
	}

	public Pair findExtrema(ArrayList<BigInteger> input, boolean isNotSorting) 
			throws ClassNotFoundException, IOException
	{	
		// Inspiration from:
		// https://www.geeksforgeeks.org/maximum-and-minimum-in-an-array/
		Pair result = getMinMax(input.toArray(new BigInteger[input.size()]), input.size());
		
		/*
		 * The algorithm correct gets the min/max...
		 * But it has result.max = min and result.min = max
		 * 
		 * This could be because in one case it says get < not <= as Protocol 2/3?
		 */
		
		// Kill the Process listening for more Protocol 2.
		// IF USING TO SORT...DO NOT DIE YET!
		if(isNotSorting)
		{
			toBob.writeBoolean(false);
		}
		
		return result;
	}
	
	// https://www.geeksforgeeks.org/maximum-and-minimum-in-an-array/
	public Pair getMinMax(BigInteger arr[], int n) 
			throws ClassNotFoundException, IOException
	{
		Pair results = new Pair();   
		int i; 

		/* If array has even number of elements then 
		    initialize the first two elements as minimum and 
		    maximum */
		//Protocol 2 works as intended here...
		if (n%2 == 0)
		{
			toBob.writeBoolean(true);
			if (Protocol2(arr[0], arr[1]) == 0)     
			{
				results.min = arr[0];
				results.max = arr[1];
				//System.err.println("Start with 0");
			}
			else
			{
				results.max = arr[0];
				results.min = arr[1];
				//System.err.println("Start with 1");
			}
			i = 2;  /* set the startung index for loop */
		}

		/* If array has odd number of elements then 
		    initialize the first element as minimum and 
		    maximum */
		else
		{
			results.min = arr[0];
			results.max = arr[0];
			i = 1;  /* set the starting index for loop */
		}

		/* In the while loop, pick elements in pair and 
		     compare the pair with max and min so far */
		
		/*
		int answer = -1;
		int a = -1;
		int b = -1;
		System.out.println("First min: " + Paillier.decrypt(results.min, server.sk) +" First max: " + Paillier.decrypt(results.max, server.sk));
		*/
		
		//min = arr[1]
		//max = arr[0]
		
		while (i < n-1)
		{
			/*
			 * For some weird reason, Protocol 2 returns the wrong answer 100% of the time
			 * when inside this while loop...
			 * So I just flip the logic and everything works...
			 * 
			 * But why is this even working???
			 */
			
			toBob.writeBoolean(true);
			//answer = Protocol2(arr[i], arr[i+1]);
			//System.out.println("Protocol 2: " + answer + " arr(i): " + Paillier.decrypt(arr[i], server.sk) +" arr(i+1): " + Paillier.decrypt(arr[i + 1], server.sk));
			
			if (Protocol2(arr[i], arr[i+1]) != 0)
			{
				toBob.writeBoolean(true);
				if((Protocol2(arr[i], results.max)) != 0)
				{
					//System.out.println("Protocol 2: " + a + " max: " + Paillier.decrypt(results.max, server.sk) +" arr(i): " + Paillier.decrypt(arr[i], server.sk));
					results.max = arr[i];
				}
				toBob.writeBoolean(true);
				if((Protocol2(arr[i+1], results.min)) != 1)
				{
					//System.out.println("Protocol 2: " + b + " arr(i+1): " + Paillier.decrypt(arr[i+1], server.sk) +" min: " + Paillier.decrypt(results.min, server.sk));
					results.min = arr[i+1];
				}
				//System.out.println("(top) new min: " + Paillier.decrypt(results.min, server.sk) +" new max: " + Paillier.decrypt(results.max, server.sk) + " given i: " + i + " and ans: " + answer);
			} 
			else        
			{
				toBob.writeBoolean(true);
				if ((Protocol2(arr[i + 1], results.max)) != 0) 
				{
					//System.out.println("Protocol 2: " + a + " max: " + Paillier.decrypt(results.max, server.sk) +" arr(i+1): " + Paillier.decrypt(arr[i+1], server.sk));
					results.max = arr[i+1];
				}
				toBob.writeBoolean(true);
				// 2 <= 46
				if ((Protocol2(arr[i], results.min)) != 1)
				{
					//System.out.println("Protocol 2: " + b + " arr(i): " + Paillier.decrypt(arr[i], server.sk) +" min: " + Paillier.decrypt(results.min, server.sk));
					results.min = arr[i];
				}
				//System.out.println("Protocol 2 parts: a, " + a + " b, " + b);
				//System.out.println("(bot) new min: " + Paillier.decrypt(results.min, server.sk) +" new max: " + Paillier.decrypt(results.max, server.sk) + " given i: " + i + " and ans: " + answer);
			}
			i += 2; /* Increment the index by 2 as two elements are processed in loop */
		}            
		return results;
	}

	
	public void sortArray() 
			throws ClassNotFoundException, IOException, InterruptedException
	{
		System.out.println("Sorting Initialized!");
		Thread t;
		
		switch(algo)
		{
			case INSERT_SORT:
				int counter = 0;
				Deque<BigInteger> minSorted = new LinkedList<>();
				Deque<BigInteger> maxSorted = new LinkedList<>();
			
				// Since I am getting two a time...be careful
				// of odd sized arrays!
				if(toSort.size() % 2 == 1)
				{
					BigInteger min = findExtrema(toSort, false).min;
					minSorted.addFirst(min);
					toSort.remove(min);
				}
				System.out.println("");
				System.err.println("Now it is an even sized list!");
				
				while(!toSort.isEmpty())
				{
					Pair res = findExtrema(toSort, false);
					minSorted.addLast(res.min);
					maxSorted.addLast(res.max);
							
					toSort.remove(res.max);
					toSort.remove(res.min);
					System.out.println("");
					System.out.println("Round: " + (++counter));
				}
				
				// Merge both dequeues!
				for(Iterator<BigInteger> itr = maxSorted.descendingIterator();itr.hasNext();)
				{
					minSorted.addLast((BigInteger) itr.next());
					//System.out.println(Paillier.decrypt((BigInteger) itr.next(), server.sk));
				}
				
				sortedArray = minSorted.toArray(new BigInteger[minSorted.size()]);
				break;
				
			case MERGE_SORT:
		        MyMergeSort mms = new MyMergeSort(toSort.toArray(new BigInteger[toSort.size()]), this);
		        (t = new Thread(mms)).start();
		        t.join();
		        sortedArray = mms.getSortedArray();
		        break;
		        
			case QUICK_SORT:
				 QuickSort qs = new QuickSort(toSort.toArray(new BigInteger[toSort.size()]), this);
				 (t = new Thread(qs)).start();
				 t.join();
				 sortedArray = qs.getSortedArray();
				 break;
				 
			default:
				break;
		}
        
        // Time to end Bob's while loop for Protocol2()
        toBob.writeBoolean(false);
	}

	
	public void closeThread() throws IOException
	{
		toBob.close();
		fromBob.close();
		if(clientSocket != null && clientSocket.isConnected())
		{
			clientSocket.close();
		}
	}
}