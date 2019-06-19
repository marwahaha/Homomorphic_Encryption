package security.socialistmillionaire;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.Socket;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Random;

import security.DGK.DGKOperations;
import security.DGK.DGKPrivateKey;
import security.DGK.DGKPublicKey;
import security.DGK.NTL;
import security.paillier.PaillierCipher;
import security.paillier.PaillierPrivateKey;
import security.paillier.PaillierPublicKey;

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
    INSERT_SORT, MERGE_SORT, QUICK_SORT, BUBBLE_SORT;
}

public class alice
{
	class Pair 
	{
		BigInteger min;
		BigInteger max;
	}
	
	private Random rnd = new Random();
	
	// Alice  will be given the Public Keys
	private PaillierPublicKey pk = null;
	private DGKPublicKey pubKey = null;
	
	// Needed for comparison
	private boolean isDGK = false;
	private BigInteger [] toSort = null;
	public BigInteger [] sortedArray = null;
	
	//I/O
	private ObjectOutputStream toBob = null;
	private ObjectInputStream fromBob = null;
	
	// Current Algorithm to Sort with...
	private Algorithm algo;
	
	// REMOVE LATER, FOR DEBUGGING
	private DGKPrivateKey privKey = null;
	private PaillierPrivateKey sk = null;
	
	public alice (Socket clientSocket,
			PaillierPublicKey _pk, DGKPublicKey _pubKey,
            boolean _isDGK, BigInteger[] _toSort) throws IOException, ClassNotFoundException
	{
		if(clientSocket != null)
		{
			toBob = new ObjectOutputStream(clientSocket.getOutputStream());
			fromBob =  new ObjectInputStream(clientSocket.getInputStream());
		}
		else
		{
			throw new NullPointerException("Client Socket is null!");
		}
		this.pk = _pk;
		this.pubKey = _pubKey;
		this.isDGK = _isDGK;
		this.toSort = _toSort;
		this.algo = Algorithm.valueOf("QUICK_SORT");
		this.receiveDGKPublicKey();
		this.receivePaillierPublicKey();
		this.getkey();
		//System.out.println(pk.toString());
		//System.out.println(pubKey.toString());
	}

	public alice (ObjectInputStream _fromBob, ObjectOutputStream _toBob,
			PaillierPublicKey _pk, DGKPublicKey _pubKey,
			boolean _isDGK, BigInteger[] _toSort) throws ClassNotFoundException, IOException
	{
		this.fromBob = _fromBob;
		this.toBob = _toBob;
		this.pk = _pk;
		this.pubKey = _pubKey;
		this.isDGK = _isDGK;
		this.toSort = _toSort;
		this.algo = Algorithm.valueOf("QUICK_SORT");
		this.getkey();
	}
	
	public boolean getDGKMode()
	{
		return isDGK;
	}
	
	public void setDGKMode(boolean _isDGK)
	{
		isDGK = _isDGK;
	}
	
	public void setSorting(ArrayList<BigInteger> _toSort)
	{
		toSort = _toSort.toArray(new BigInteger[_toSort.size()]);
	}
	
	public PaillierPublicKey getPaiilierPublicKey()
	{
		return pk;
	}
	
	public DGKPublicKey getDGKPublicKey()
	{
		return pubKey;
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

	public int Protocol1(BigInteger x) throws IOException, ClassNotFoundException
	{
		int answer = -1;
		int deltaB = -1;
		int deltaA = rnd.nextInt(2);
		Object in;
		BigInteger [] Encrypted_Y;
		BigInteger [] C;
		
		// Step 1: Get Y bits from Bob
		in = fromBob.readObject();
		if (in instanceof BigInteger[])
		{
			Encrypted_Y = (BigInteger []) in;
		}
		else
		{
			throw new IllegalArgumentException("Protocol 3 Step 1: Missing Y-bits!");
		}

		if (x.bitLength() < Encrypted_Y.length)
		{
			toBob.writeObject(BigInteger.ONE);
			toBob.flush();
			return 1;
		}
		else if(x.bitLength() > Encrypted_Y.length)
		{
			toBob.writeObject(BigInteger.ZERO);
			toBob.flush();
			return 0;
		}

		// Otherwise, if bit size is equal, proceed!
		// Step 2: compute Encrypted X XOR Y
		BigInteger [] XOR = new BigInteger[Encrypted_Y.length];
		for (int i = 0; i < Encrypted_Y.length; i++)
		{
			//Enc[x XOR y] = [y_i]
			if (NTL.bit(x, i) == 0)
			{
				XOR[i] = Encrypted_Y[i];
			}
			//Enc[x XOR y] = [1] - [y_i]
			else
			{
				XOR[i] = DGKOperations.DGKSubtract(pubKey, 
						DGKOperations.encrypt(pubKey, 1), 
						Encrypted_Y[i]);
			}
		}
	
		// Step 3: Alice picks deltaA and computes S
		BigInteger s = DGKOperations.encrypt(pubKey, 1 - 2 * deltaA);
		
		// Step 4: Compute C_i
		C = new BigInteger[Encrypted_Y.length + 1];
		BigInteger product;
		BigInteger [] temp = new BigInteger[Encrypted_Y.length];
		
		// Compute the Product of XOR, add s and compute x - y
		for (int i = 0; i < Encrypted_Y.length;i++)
		{
			// Compute product and multiply by 3
			product = DGKOperations.DGKSum(pubKey, XOR, Encrypted_Y.length - 1 - i);
			C[Encrypted_Y.length - 1 - i] = DGKOperations.DGKMultiply(pubKey, product, 3);
			// C_i += s
			C[Encrypted_Y.length - 1 - i] = DGKOperations.DGKAdd(pubKey, s, C[Encrypted_Y.length - 1 - i]);
			temp[i] = DGKOperations.DGKSubtract(pubKey, DGKOperations.encrypt(pubKey, NTL.bit(x, i)), Encrypted_Y[i]);
		}
		
		for (int i = 0; i < Encrypted_Y.length;i++)
		{
			C[i] = DGKOperations.DGKAdd(pubKey, C[i], temp[i]);
		}
		
		//This is c_{-1}
		C[Encrypted_Y.length] = DGKOperations.DGKSum(pubKey, XOR);
		C[Encrypted_Y.length] = DGKOperations.DGKAdd(pubKey, C[Encrypted_Y.length], DGKOperations.encrypt(pubKey, deltaA));

		// Step 5: Blinds C_i and send to Bob
		for (int i = 0; i < Encrypted_Y.length;i++)
		{
			C[i] = DGKOperations.DGKMultiply(pubKey, C[i], 1);
		}
		toBob.writeObject(C);
		toBob.flush();
		
		// Step 6: Bob looks for any 0's in C_i and computes DeltaB
		
		// Step 7: Obtain Delta B from Bob
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
		toBob.writeObject(DGKOperations.encrypt(pubKey, BigInteger.valueOf(answer)));
		toBob.flush();
		return answer;
	}
	
	public int Protocol2(BigInteger x, BigInteger y) 
			throws IOException, ClassNotFoundException
	{	
		int deltaB = -1;
		int deltaA = rnd.nextInt(2);
		int x_leq_y = -1;
		int comparison = -1;
		BigInteger z = null;
		BigInteger zdiv2L =  null;
		BigInteger result = null;
		Object bob = null;
		BigInteger r = null;
		BigInteger powL = BigInteger.valueOf(exponent(2, pubKey.l));

		// Step 1: 0 <= r < N
		// Pick Number of l + 1 + sigma bits
		// Considering DGK is an option, just stick with size of Zu
		if (isDGK)
		{
			r = NTL.RandomBnd((pubKey.u - 1)/2);
		}
		else
		{
			r = NTL.RandomBnd(pubKey.l + 1 + 80);
		}
		
		/*
		 * Step 2: Alice computes [[z]] = [[x - y + 2^l + r]]
		 * Send Z to Bob
		 * [[x + 2^l + r]]
		 * [[z]] = [[x - y + 2^l + r]]
		 */
		if (isDGK)
		{
			z = DGKOperations.DGKAdd(pubKey, x, DGKOperations.encrypt(pubKey, r.add(powL).mod(pubKey.bigU)));
			z = DGKOperations.DGKSubtract(pubKey, z, y);
		}
		else
		{
			z = PaillierCipher.add(x, PaillierCipher.encrypt(r.add(powL), pk), pk);
            z = PaillierCipher.subtract(z, y, pk);
		}
		toBob.writeObject(z);
		toBob.flush();
		
		// Step 2: Bob decrypts[[z]] and computes beta = z (mod 2^l)

		// Step 3: alpha = r (mod 2^l)
		BigInteger alphaZZ = NTL.POSMOD(r, powL);

		// Step 4: Complete Protocol 1 or Protocol 3
        x_leq_y = Protocol3(alphaZZ, deltaA);
        System.out.println("alphaZZ: " + alphaZZ);
        System.out.println("Result: " + x_leq_y);
    	
		// Step 5: Bob sends z/2^l and GammaB 
		bob = fromBob.readObject();
		if (bob instanceof BigInteger)
		{
			zdiv2L = (BigInteger) bob;
		}
		else
		{
			throw new IllegalArgumentException("Protocol 2, Step 5: BigInteger not found!");
		}

		/*
		 * Step 6
		 * Since I know deltaA and result of Protocol 3,
		 * I can infer deltaB from Bob.
		 * 
		 * Inputting (beta <= alpha) is in Step 7.
		 */
    	if(deltaA == x_leq_y)
        {
            deltaB = 0;
        }
        else
        {
            deltaB = 1;
        }

		/*
		 * Step 7, Alice Computes [[x <= y]]
		 * = [[z/2^l]] * ([[r/2^l]] [[alpha < Beta]])^-1 
		 * = [[z/2^l - r/2^l - (alpha <= beta)]]
		 */
		if(isDGK)
		{
			result = DGKOperations.DGKSubtract(pubKey, zdiv2L, DGKOperations.encrypt(pubKey, r.divide(powL)));
			System.out.println("result: " + DGKOperations.decrypt(pubKey, privKey, result));
			if(deltaA == 1)
			{
				result = DGKOperations.DGKSubtract(pubKey, result, DGKOperations.encrypt(pubKey, deltaB));
			}
			else
			{
				result = DGKOperations.DGKSubtract(pubKey, result, DGKOperations.encrypt(pubKey, 1 - deltaB));
			}
			System.out.println("FINAL result: " + DGKOperations.decrypt(pubKey, privKey, result));
		}
		else
		{
           result = PaillierCipher.subtract(zdiv2L, PaillierCipher.encrypt(r.divide(powL), pk), pk);
           System.out.println("result: " + PaillierCipher.decrypt(result, sk));
           if(deltaA == 1)
           {
               result = PaillierCipher.subtract(result, PaillierCipher.encrypt(deltaB, pk), pk);
           }
           else
           {
               result = PaillierCipher.subtract(result, PaillierCipher.encrypt((1 - deltaB), pk), pk);
           }
           System.out.println("FINAL result: " + PaillierCipher.decrypt(result, sk));
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
		// IF SOMETHING HAPPENS...GET POST MORTERM HERE
		if (comparison != 0 && comparison != 1)
		{
			System.err.println("Comparison result: " + comparison);
		}
		return comparison;
	}
	
	public int Protocol3(BigInteger x) throws ClassNotFoundException, IOException
	{
		return Protocol3(x, rnd.nextInt(2));
	}

	/*
	 * Input Alice: x (unencrypted BigInteger x)
	 * Input Bob: y (unencrypted BigInteger y), Private Keys
	 * 
	 * Result: [[x <= y]] or [x <= y]
	 * Alice and Bob WITHOUT revealing x, y
	 * It is boolean value! 
	 * x <= y -> [[1]]
	 * x > y -> [[0]]
	 */

	private int Protocol3(BigInteger x, int _deltaA)
			throws ClassNotFoundException, IOException
	{	
		int deltaA = rnd.nextInt(2);
		if (_deltaA == 0 || _deltaA == 1)
		{
			deltaA = _deltaA;
		}
		BigInteger [] Encrypted_Y;
		int deltaB;
		int answer;
		Object in;

		//Step 1: Receive y_i bits from Bob
		in = fromBob.readObject();
		if (in instanceof BigInteger[])
		{
			Encrypted_Y = (BigInteger []) in;
		}
		else
		{
			throw new IllegalArgumentException("Protocol 3 Step 1: Missing Y-bits!");
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
		if (x.bitLength() < Encrypted_Y.length)
		{
			toBob.writeObject(BigInteger.ONE);
			toBob.flush();
			// x <= y -> 1 (true)
			return 1;
		}

		// Case 2 delta B is 0
		// x has more bits -> x is bigger
		else if(x.bitLength() > Encrypted_Y.length)
		{
			toBob.writeObject(BigInteger.ZERO);
			toBob.flush();
			// x <= y -> 0 (false)
			return 0;
		}

		// if equal bits, proceed!
		// Step 2: compute Encrypted X XOR Y
		BigInteger [] XOR = new BigInteger[Encrypted_Y.length];
		for (int i = 0; i < Encrypted_Y.length; i++)
		{
			//Enc[x XOR y] = [y_i]
			if (NTL.bit(x, i) == 0)
			{
				XOR[i] = Encrypted_Y[i];
			}
			//Enc[x XOR y] = [1] - [y_i]
			else
			{
				XOR[i] = DGKOperations.DGKSubtract(pubKey, DGKOperations.encrypt(pubKey, 1), 
						Encrypted_Y[i]);
			}
		}
		
		// Step 3A: delta A is computed on initialization, it is 0 or 1.
		// Step 3B: Collect index of all index where x_i = GammaA
		ArrayList <Integer> ListofGammaA = new ArrayList<>();
		for (int i = 0;i < Encrypted_Y.length + 1; i++)
		{
			if (NTL.bit(x, i) == deltaA)
			{
				ListofGammaA.add(i);
			}
		}

		// Step 4A: Generate C_i, see c_{-1} to test for equality!
		// C_{-1} = C_i[yBits], will be computed at the end...
		BigInteger [] C_i = new BigInteger [Encrypted_Y.length + 1];
		
		BigInteger product = DGKOperations.encrypt(pubKey, 0);
		for (int i = 0; i < Encrypted_Y.length; i++)
		{
			// Goes from yBits - 1 to 0
			C_i [Encrypted_Y.length - 1 - i] = product;
			product = DGKOperations.DGKAdd(pubKey, product, XOR[i]);
		}

		/*
		 * Step 4B: alter C_i using Gamma A
		 * Also compute:
		 * [1] - [y_i bit]
		 */

		BigInteger [] minus = new BigInteger[Encrypted_Y.length];
		if (deltaA == 0)
		{
			for(int i = 0; i < Encrypted_Y.length; i++)
			{
				minus [i] = DGKOperations.DGKSubtract(pubKey, DGKOperations.encrypt(pubKey, 1), 
						Encrypted_Y[i]);
			}
		}
		
		for (int i = 0; i < Encrypted_Y.length; i++)
		{
			if (deltaA==0)
			{
				// Step 4 = [1] - [y_i bit] + [c_i]
				C_i[i] = DGKOperations.DGKAdd(pubKey, C_i[i], minus[Encrypted_Y.length - 1 - i]);
			}
			else
			{
				// Step 4 = [y_i] + [c_i]
				C_i[i]= DGKOperations.DGKAdd(pubKey, C_i[i], Encrypted_Y[Encrypted_Y.length - 1 - i]);
			}
		}

		//Step 5: Apply the Blinding to C_i and send it to Bob
		for (int i = 0; i < Encrypted_Y.length;i++)
		{
			// if i is NOT in L, just place a random NON-ZERO
			if(!ListofGammaA.contains(i))
			{
				C_i[Encrypted_Y.length - 1 - i] = DGKOperations.encrypt(pubKey, 7);
			}
		}
		
		//This is c_{-1}
		C_i[Encrypted_Y.length] = DGKOperations.DGKSum(pubKey, XOR);	//This is your c_{-1}
		C_i[Encrypted_Y.length] = DGKOperations.DGKAdd(pubKey, C_i[Encrypted_Y.length], DGKOperations.encrypt(pubKey, deltaA));

		//Send to Bob, C_i and sum of XOR (equality check)
		toBob.writeObject(C_i);
		toBob.flush();

		// Step 7: Obtain Delta B from Bob
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
		toBob.writeObject(DGKOperations.encrypt(pubKey, BigInteger.valueOf(answer)));
		toBob.flush();
		return answer;
	}

	public int Protocol4(BigInteger x, BigInteger y) 
			throws IOException, ClassNotFoundException
	{
		int deltaB = -1;
		int deltaA = rnd.nextInt(2);
		int x_leq_y = -1;
		int comparison = -1;
		BigInteger z = null;
		BigInteger zdiv2L =  null;
		BigInteger result = null;
		Object bob = null;
		BigInteger r = null;
		BigInteger powL = BigInteger.valueOf(exponent(2, pubKey.l));

		// Step 1: 0 <= r < N
		// Pick Number of l + 1 + sigma bits
		// Considering DGK is an option, just stick with size of Zu
		if (isDGK)
		{
			r = NTL.RandomBnd((pubKey.u - 1)/2);
		}
		else
		{
			r = NTL.RandomBnd(pubKey.l + 1 + 80);
		}
		
		/*
		 * Step 2: Alice computes [[z]] = [[x - y + 2^l + r]]
		 * Send Z to Bob
		 * [[x + 2^l + r]]
		 * [[z]] = [[x - y + 2^l + r]]
		 */
		if (isDGK)
		{
			z = DGKOperations.DGKAdd(pubKey, x, DGKOperations.encrypt(pubKey, r.add(powL).mod(pubKey.bigU)));
			z = DGKOperations.DGKSubtract(pubKey, z, y);
		}
		else
		{
			z = PaillierCipher.add(x, PaillierCipher.encrypt(r.add(powL), pk), pk);
            z = PaillierCipher.subtract(z, y, pk);
		}
		toBob.writeObject(z);
		toBob.flush();
		
		// Step 2: Bob decrypts[[z]] and computes beta = z (mod 2^l)

		// Step 3: alpha = r (mod 2^l)
		BigInteger alphaZZ = NTL.POSMOD(r, powL);

		// Step 4: Complete Protocol 1 or Protocol 3
        x_leq_y = Modified_Protocol3(alphaZZ, r, deltaA);
        System.out.println("alphaZZ: " + alphaZZ);
        System.out.println("Result: " + x_leq_y);
    	
		// Step 5: Bob sends z/2^l and GammaB 
		bob = fromBob.readObject();
		if (bob instanceof BigInteger)
		{
			zdiv2L = (BigInteger) bob;
		}
		else
		{
			throw new IllegalArgumentException("Protocol 2, Step 5: BigInteger not found!");
		}

		/*
		 * Step 6
		 * Since I know deltaA and result of Protocol 3,
		 * I can infer deltaB from Bob.
		 * 
		 * Inputting (beta <= alpha) is in Step 7.
		 */
    	if(deltaA == x_leq_y)
        {
            deltaB = 0;
        }
        else
        {
            deltaB = 1;
        }

		/*
		 * Step 7, Alice Computes [[x <= y]]
		 * = [[z/2^l]] * ([[r/2^l]] [[alpha < Beta]])^-1 
		 * = [[z/2^l - r/2^l - (alpha <= beta)]]
		 */
		if(isDGK)
		{
			result = DGKOperations.DGKSubtract(pubKey, zdiv2L, DGKOperations.encrypt(pubKey, r.divide(powL)));
			System.out.println("result: " + DGKOperations.decrypt(pubKey, privKey, result));
			if(deltaA == 1)
			{
				result = DGKOperations.DGKSubtract(pubKey, result, DGKOperations.encrypt(pubKey, deltaB));
			}
			else
			{
				result = DGKOperations.DGKSubtract(pubKey, result, DGKOperations.encrypt(pubKey, 1 - deltaB));
			}
			System.out.println("FINAL result: " + DGKOperations.decrypt(pubKey, privKey, result));
		}
		else
		{
           result = PaillierCipher.subtract(zdiv2L, PaillierCipher.encrypt(r.divide(powL), pk), pk);
           System.out.println("result: " + PaillierCipher.decrypt(result, sk));
           if(deltaA == 1)
           {
               result = PaillierCipher.subtract(result, PaillierCipher.encrypt(deltaB, pk), pk);
           }
           else
           {
               result = PaillierCipher.subtract(result, PaillierCipher.encrypt((1 - deltaB), pk), pk);
           }
           System.out.println("FINAL result: " + PaillierCipher.decrypt(result, sk));
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
		// IF SOMETHING HAPPENS...GET POST MORTERM HERE
		if (comparison != 0 && comparison != 1)
		{
			System.err.println("Comparison result: " + comparison);
		}
		return comparison;
	}
	
	public int Modified_Protocol3(BigInteger alpha, BigInteger r)
			throws ClassNotFoundException, IOException
	{
		return Modified_Protocol3(alpha, r, rnd.nextInt(2));
	}
	
	// Modified Protocol 3 for Protocol 4
	// This should mostly use ONLY DGK stuff!
	private int Modified_Protocol3(BigInteger alpha, BigInteger r, int _deltaA) 
			throws ClassNotFoundException, IOException
	{
		if (alpha == null)
		{
			alpha = r.mod(BigInteger.valueOf(exponent(2, pubKey.l)));
		}
		int deltaA;
		if(_deltaA == 0 || _deltaA == 1)
		{			
			deltaA = _deltaA;
		}
		else
		{
			deltaA = rnd.nextInt(2);;
		}
		int answer;
		Object in;
		BigInteger [] beta_bits = null;
		BigInteger [] encAlphaXORBeta = null;
		BigInteger [] w = null;
		BigInteger [] C = null;
		BigInteger alpha_hat = null;
		BigInteger d = null;
		
		// Step A: get d from Bob
		in = fromBob.readObject();
		if (in instanceof BigInteger)
		{
			d = (BigInteger) in;
		}
		else
		{
			throw new IllegalArgumentException("BigInteger: d not found!");
		}
		
		// Step B: get beta_bits from Bob
		in = fromBob.readObject();
		if (in instanceof BigInteger[])
		{
			beta_bits = (BigInteger []) in;
		}
		else
		{
			throw new IllegalArgumentException("BigInteger []: C not found!");
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

		if (alpha.bitLength() < beta_bits.length)
		{
			toBob.writeObject(BigInteger.ONE);
			toBob.flush();
			return 1;
		}
		else if(alpha.bitLength() > beta_bits.length)
		{
			toBob.writeObject(BigInteger.ZERO);
			toBob.flush();
			return 0;
		}
		
		// Step C: Alice corrects d...
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
				encAlphaXORBeta[i] = DGKOperations.DGKSubtract(pubKey, 
						DGKOperations.encrypt(pubKey, 1), beta_bits[i]);				
			}
		}
		
		// Step E: Compute Alpha Hat
		if (isDGK)
		{
			alpha_hat = r.subtract(pk.n).mod(BigInteger.valueOf(exponent(2, pubKey.l)));
		}
		else
		{
			alpha_hat = r.subtract(pubKey.bigU).mod(BigInteger.valueOf(exponent(2, pubKey.l)));
		}
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
		
		// Step F: See optimization...
		for (int i = 0; i < beta_bits.length;i++)
		{
			if(NTL.bit(alpha_hat, i) == NTL.bit(alpha, i))
			{
				w[i] = DGKOperations.DGKMultiply(pubKey, w[i], pubKey.l);	
			}
		}
		
		// Step G: Delta A computed at start!
		BigInteger S = DGKOperations.encrypt(pubKey, 1 - (2 * deltaA));
		
		// Step H:
		BigInteger product;
		long exponent;
		C = new BigInteger[beta_bits.length + 1];
		BigInteger [] temp = new BigInteger[beta_bits.length];
		for (int i = 0; i < beta_bits.length;i++)
		{
			// Compute product and multiply by 3
			product = DGKOperations.DGKSum(pubKey, w, beta_bits.length - 1 - i);
			C[beta_bits.length - 1 - i] = DGKOperations.DGKMultiply(pubKey, product, 3);
			// C_i += s
			C[beta_bits.length - 1 - i] = DGKOperations.DGKAdd(pubKey, S, C[beta_bits.length - 1 - i]);
			
			// t = alpha_i - beta_i
			temp[i] = DGKOperations.DGKSubtract(pubKey, DGKOperations.encrypt(pubKey, NTL.bit(alpha, i)), beta_bits[i]);
			exponent = NTL.bit(alpha_hat, i) - NTL.bit(alpha, i);
			// t = d^{a - a}
			temp[i] = DGKOperations.DGKAdd(pubKey, temp[i], DGKOperations.DGKMultiply(pubKey, d, exponent));
		}
		
		// Combine terms!
		for(int i = 0; i < beta_bits.length;i++)
		{
			C[i] = DGKOperations.DGKAdd(pubKey, C[i], temp[i]);
		}
		
		//This is c_{-1}
		C[beta_bits.length] = DGKOperations.DGKSum(pubKey, encAlphaXORBeta);
		C[beta_bits.length] = DGKOperations.DGKAdd(pubKey, C[beta_bits.length], DGKOperations.encrypt(pubKey, deltaA));

		// Step I: BLIND THE EXPONENTS AND SEND TO BOB
		for (int i = 0; i < beta_bits.length;i++)
		{
			C[i] = DGKOperations.DGKMultiply(pubKey, C[i], 1);
		}
		toBob.writeObject(C);
		toBob.flush();
		
		// Step J: Bob checks whether a C_i has a zero or not...get delta B.
		int deltaB = fromBob.readInt();
		if (deltaA == deltaB)
		{
			answer = 0;
		}
		else
		{
			answer = 1;
		}
		toBob.writeObject(DGKOperations.encrypt(pubKey, answer));
		toBob.flush();
		return answer;
	}
	
	/*
	 * See Protocol 2:
	 * Encrypted Integer Division by
	 * Thjis Veugen
	 * 
	 * Input Alice: [x] and d
	 * Input Bob: d, and Private Key K
	 * Output Alice: [x/d]
	 * Constraints: 0 <= x <= N * 2^{-sigma} and 0 <= d < N
	 * sigma = 80 usually?
	 */
	
	public BigInteger division(BigInteger x, int d) 
			throws IOException, ClassNotFoundException
	{
		Object in;
		BigInteger answer;
		BigInteger c = null;
		BigInteger z = null;
		BigInteger r = null;
		
		// Step 1
		if(isDGK)
		{
			r = NTL.RandomBnd(log2((int) (pubKey.u - 1)/2));
			z = DGKOperations.DGKAdd(pubKey, x, DGKOperations.encrypt(pubKey, r));
		}
		else
		{
			r = NTL.RandomBnd(pk.n.subtract(BigInteger.ONE).divide(new BigInteger("2")));
			z = PaillierCipher.add(x, PaillierCipher.encrypt(r, pk), pk);
		}
		toBob.writeObject(z);
		toBob.flush();
		
		// Step 2: Executed by Bob
		
		// Step 3: Compute secure comparison Protocol 
		int t = Protocol3(r.mod(BigInteger.valueOf(d)), 20);
		
		// Step 4: Bob computes c and Alice receives it
		in = fromBob.readObject();
		if (in instanceof BigInteger)
		{
			c = (BigInteger) in;
		}
		else
		{
			throw new IllegalArgumentException("Alice: BigInteger not found!");
		}
		
		// Step 5: Alice computes [x/d]
		// [[z/d - r/d]]
		// [[z/d - r/d - t]]
		if (isDGK)
		{
			answer = DGKOperations.DGKSubtract(pubKey, c, DGKOperations.encrypt(pubKey, r.divide(BigInteger.valueOf(d))));
			answer = DGKOperations.DGKSubtract(pubKey, answer, DGKOperations.encrypt(pubKey, t));
			answer = DGKOperations.DGKAdd(pubKey, answer, DGKOperations.encrypt(pubKey, 1));
		}
		else
		{
			answer = PaillierCipher.subtract(c, PaillierCipher.encrypt(r.divide(BigInteger.valueOf(d)), pk), pk);
			answer = PaillierCipher.subtract(answer, PaillierCipher.encrypt(BigInteger.valueOf(t), pk), pk);
			answer = PaillierCipher.add(answer, PaillierCipher.encrypt(BigInteger.ONE, pk), pk);
		}
		
		// Print Answer to verify
		if(isDGK)
		{
			System.out.println("answer: " + DGKOperations.decrypt(pubKey, privKey, answer));	
		}
		else
		{
			System.out.println("answer: " + PaillierCipher.decrypt(answer, sk));	
		}
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
			i = 2;  /* set the starting index for loop */
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

	public BigInteger[] sortArray() 
			throws ClassNotFoundException, IOException
	{
		System.out.println("Sorting Initialized!");
		if(toSort == null)
		{
			sortedArray = new BigInteger[0];
			return sortedArray;
		}
		if(toSort.length == 1 || toSort.length == 0)
		{
			sortedArray = toSort;
			return sortedArray;
		}
		else if (toSort.length == 2)
		{
			ArrayList<BigInteger> Sort = new ArrayList<BigInteger>(Arrays.asList(toSort));
			Pair result = findExtrema(Sort, true);
			sortedArray = new BigInteger[2];
			sortedArray[0] = result.min;
			sortedArray[1] = result.max;
			toBob.writeBoolean(false);
			return sortedArray;
		}
		
		switch(algo)
		{
			case INSERT_SORT:
				ArrayList<BigInteger> Sort = new ArrayList<BigInteger>(Arrays.asList(toSort));
				int counter = 0;
				Deque<BigInteger> minSorted = new LinkedList<>();
				Deque<BigInteger> maxSorted = new LinkedList<>();
			
				// Since I am getting two a time...be careful
				// of odd sized arrays!
				if(Sort.size() % 2 == 1)
				{
					BigInteger min = findExtrema(Sort, false).min;
					minSorted.addFirst(min);
					Sort.remove(min);
				}
				System.err.println("Now it is an even sized list!");
				
				while(!Sort.isEmpty())
				{
					Pair res = findExtrema(Sort, false);
					minSorted.addLast(res.min);
					maxSorted.addLast(res.max);
					Sort.remove(res.max);
					Sort.remove(res.min);
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
		        MyMergeSort mms = new MyMergeSort(toSort, this);
		        mms.doMergeSort(0, toSort.length - 1);
		        sortedArray = mms.getSortedArray();
		        break;
		        
			case QUICK_SORT:
				QuickSort qs = new QuickSort(toSort, this);
				qs.sort(toSort, 0, toSort.length - 1);
				sortedArray = qs.getSortedArray();
				break;
				
			case BUBBLE_SORT:
				BubbleSort bubble = new BubbleSort(toSort, this);
				bubble.bubbleSort();
				sortedArray = bubble.getSortedArray();
			default:
				break;
		}
        // Time to end Bob's while loop for Protocol2()
        toBob.writeBoolean(false);
        return sortedArray;
	}
	
	public void receiveDGKPublicKey() throws IOException, ClassNotFoundException
	{
		Object x = fromBob.readObject();
		if (x instanceof DGKPublicKey)
		{
			pubKey = (DGKPublicKey) x;
		}
		else
		{
			throw new IllegalArgumentException("DGK Public Key not obtained!");
		}
	}
	
	public void receivePaillierPublicKey() throws IOException, ClassNotFoundException
	{
		Object x = fromBob.readObject();
		if(x instanceof PaillierPublicKey)
		{
			pk = (PaillierPublicKey) x;
		}
		else
		{
			throw new IllegalArgumentException("Paillier Public Key not obtained!");
		}
	}
	
	public void close() throws IOException
	{
		toBob.close();
		fromBob.close();
	}
	
	// Debug Protocol 1 and 3
	public void print_bits(BigInteger [] bits) throws ClassNotFoundException, IOException
	{
		for (int i = 0; i < bits.length; i++)
		{
			if (bits[i] != null)
			{
				System.out.print(DGKOperations.decrypt(pubKey, privKey, bits[i]) + ",");
			}
			else
			{
				System.out.print("NULL");
			}
		}
		System.out.println("");
	}
	
	public void getkey() throws ClassNotFoundException, IOException
	{
		Object in;
		in = fromBob.readObject();
		if (in instanceof DGKPrivateKey)
		{
			privKey = (DGKPrivateKey) in;
		}
		else
		{
			System.err.println("BAD DGK");
		}
		in = fromBob.readObject();
		if (in instanceof PaillierPrivateKey)
		{
			sk = (PaillierPrivateKey) in;
		}
		else
		{
			System.err.println("BAD PAILLIER");
		}
	}
	
	public boolean is_valid_DGK_KeyPair()
	{
		BigInteger init = new BigInteger("60");
		long test;
		BigInteger t = DGKOperations.encrypt(pubKey, init);
		test = DGKOperations.decrypt(pubKey, privKey, t);
		return BigInteger.valueOf(test).compareTo(init) == 0;
	}
	
	public boolean is_valid_Paillier_KeyPair()
	{
		BigInteger init = new BigInteger("60");
		BigInteger t = PaillierCipher.encrypt(init, pk);
		t = PaillierCipher.decrypt(t, sk);
		return t.compareTo(init) == 0;
	}
}
