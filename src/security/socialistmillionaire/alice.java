package security.socialistmillionaire;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.Socket;
import java.security.SecureRandom;
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

/*
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

public class alice implements Runnable
{
	private class Pair 
	{
		BigInteger min;
		BigInteger max;
	}
	
	private SecureRandom rnd = new SecureRandom();
	// See Veugen paper, security parameter for Paillier
	private final static int SIGMA = 80;
	
	// Alice  will be given the Public Keys
	private PaillierPublicKey pk = null;
	private DGKPublicKey pubKey = null;
	
	// Needed for comparison
	private boolean isDGK = false;
	private BigInteger [] toSort = null;
	private BigInteger [] sortedArray = null;
	
	//I/O
	private ObjectOutputStream toBob = null;
	private ObjectInputStream fromBob = null;
	
	// Current Algorithm to Sort with
	private Algorithm algo;
	
	// ONLY USED FOR DEBUGGING
	private DGKPrivateKey privKey = null;
	private PaillierPrivateKey sk = null;
	
	// Temporary for Merge Sort
    private BigInteger [] tempBigMerg = null;
    
	public alice (Socket clientSocket,
            boolean isDGK) throws IOException, ClassNotFoundException
	{
		this(clientSocket, null, null, isDGK, null);
		receiveDGKPublicKey();
		receivePaillierPublicKey();
	}
	
	public alice (Socket clientSocket,
            boolean isDGK, BigInteger[] toSort) throws IOException, ClassNotFoundException
	{
		this(clientSocket, null, null, isDGK, toSort);
		receiveDGKPublicKey();
		receivePaillierPublicKey();
	}
	
	public alice (Socket clientSocket,
			PaillierPublicKey pk, DGKPublicKey pubKey,
            boolean isDGK, BigInteger[] toSort) throws IOException, ClassNotFoundException
	{
		if(clientSocket != null)
		{
			toBob = new ObjectOutputStream(clientSocket.getOutputStream());
			fromBob = new ObjectInputStream(clientSocket.getInputStream());
		}
		else
		{
			throw new NullPointerException("Client Socket is null!");
		}
		this.pk = pk;
		this.pubKey = pubKey;
		this.isDGK = isDGK;
		this.toSort = toSort;
		this.algo = Algorithm.valueOf("QUICK_SORT");
		
		// ONLY FOR DEBUGGING
		this.getkey();
	}

	public alice (ObjectInputStream fromBob, ObjectOutputStream toBob,
			PaillierPublicKey pk, DGKPublicKey pubKey,
			boolean isDGK, BigInteger[] toSort) throws ClassNotFoundException, IOException
	{
		this.fromBob = fromBob;
		this.toBob = toBob;
		this.pk = pk;
		this.pubKey = pubKey;
		this.isDGK = isDGK;
		this.toSort = toSort;
		this.algo = Algorithm.valueOf("QUICK_SORT");
		this.getkey();
	}
	
	public boolean getDGKMode()
	{
		return isDGK;
	}
	
	public void setDGKMode(boolean isDGK)
	{
		this.isDGK = isDGK;
	}
	
	public void setSorting(ArrayList<BigInteger> toSort)
	{
		this.toSort = toSort.toArray(new BigInteger[toSort.size()]);
	}
	
	public void setSorting(BigInteger [] toSort)
	{
		toSort = this.toSort;
	}
	
	public BigInteger [] getSortedArray()
	{
		return sortedArray;
	}
	
	public PaillierPublicKey getPaiilierPublicKey()
	{
		return pk;
	}
	
	public DGKPublicKey getDGKPublicKey()
	{
		return pubKey;
	}

	private static int exponent(int base, int exponent)
	{
		int answer = 1;
		int counter = exponent;
		while (counter != 0)
		{
			answer *= base;
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
		Object in = null;
		BigInteger [] Encrypted_Y = null;
		BigInteger [] C = null;
		BigInteger [] XOR = null;
		
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
		XOR = new BigInteger[Encrypted_Y.length];
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
				XOR[i] = DGKOperations.subtract(pubKey, pubKey.ONE(), Encrypted_Y[i]);
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
			product = DGKOperations.sum(pubKey, XOR, Encrypted_Y.length - 1 - i);
			C[Encrypted_Y.length - 1 - i] = DGKOperations.multiply(pubKey, product, 3);
			// C_i += s
			C[Encrypted_Y.length - 1 - i] = DGKOperations.add(pubKey, s, C[Encrypted_Y.length - 1 - i]);
			temp[i] = DGKOperations.subtract(pubKey, DGKOperations.encrypt(pubKey, NTL.bit(x, i)), Encrypted_Y[i]);
		}
		
		for (int i = 0; i < Encrypted_Y.length;i++)
		{
			C[i] = DGKOperations.add(pubKey, C[i], temp[i]);
		}
		
		//This is c_{-1}
		C[Encrypted_Y.length] = DGKOperations.sum(pubKey, XOR);
		C[Encrypted_Y.length] = DGKOperations.add(pubKey, C[Encrypted_Y.length], DGKOperations.encrypt(pubKey, deltaA));

		// Step 5: Blinds C_i, Shuffle it and send to Bob
		for (int i = 0; i < C.length; i++)
		{
			C[i] = DGKOperations.multiply(pubKey, C[i], rnd.nextInt(pubKey.l) + 1);
		}
		C = shuffle_bits(C);
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
		BigInteger alpha_lt_beta = null;
		BigInteger z = null;
		BigInteger zdiv2L =  null;
		BigInteger result = null;
		Object bob = null;
		BigInteger r = null;
		BigInteger powL = null;
		BigInteger zeta_one = null;
		BigInteger zeta_two = null;

		// Step 1: 0 <= r < N
		// Pick Number of l + 1 + sigma bits
		// Considering DGK is an option, just stick with size of Zu
		
		if (isDGK)
		{
			r = NTL.RandomBnd(pubKey.u);
			powL = BigInteger.valueOf(exponent(2, pubKey.l - 2));
		}
		else
		{
			// Generate Random Number with l + 1 + sigma bits
			if (pubKey.l + SIGMA < pk.keysize)
			{
				r = NTL.generateXBitRandom(pubKey.l + 1 + SIGMA);
			}
			else
			{
				throw new IllegalArgumentException("Invalid due to constraints!");
			}
			powL = BigInteger.valueOf(exponent(2, pubKey.l));
		}
		
		/*
		 * Step 2: Alice computes [[z]] = [[x - y + 2^l + r]]
		 * Send Z to Bob
		 * [[x + 2^l + r]]
		 * [[z]] = [[x - y + 2^l + r]]
		 */
		if (isDGK)
		{
			z = DGKOperations.add(pubKey, x, DGKOperations.encrypt(pubKey, r.add(powL).mod(pubKey.bigU)));
			z = DGKOperations.subtract(pubKey, z, y);
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
        //System.out.println("Protocol 2 alphaZZ: " + alphaZZ);
        //System.out.println("Protocol 3 Result: " + x_leq_y);
    	
		// Step 5: Bob sends z/2^l and GammaB 
		bob = fromBob.readObject();
		if (bob instanceof BigInteger)
		{
			zeta_one = (BigInteger) bob;
		}
		else
		{
			throw new IllegalArgumentException("Protocol 2, Step 5: BigInteger not found!");
		}
		
		bob = fromBob.readObject();
		if (bob instanceof BigInteger)
		{
			zeta_two = (BigInteger) bob;
		}
		else
		{
			throw new IllegalArgumentException("Protocol 2, Step 5: BigInteger not found!");
		}
		
		if(isDGK)
		{
			if (r.longValue() < (pubKey.u - 1)/2)
			{
				zdiv2L = zeta_one;
			}
			else
			{
				zdiv2L = zeta_two;
			}
		}
		else
		{
			if (r.compareTo(pk.n.subtract(BigInteger.ONE).divide(new BigInteger("2"))) == 0)
			{
				zdiv2L = zeta_one;
			}
			else
			{
				zdiv2L = zeta_two;
			}
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
    	
    	if (isDGK)
    	{
			if(deltaA == 1)
			{
				alpha_lt_beta = DGKOperations.encrypt(pubKey, deltaB);
			}
			else
			{
				alpha_lt_beta = DGKOperations.encrypt(pubKey, 1 - deltaB);
			}
    	}
    	else
    	{
            if(deltaA == 1)
            {
            	alpha_lt_beta = PaillierCipher.encrypt(deltaB, pk);
            }
            else
            {
            	alpha_lt_beta = PaillierCipher.encrypt((1 - deltaB), pk);
            }
    	}

		/*
		 * Step 7, Alice Computes [[x <= y]]
		 * = [[z/2^l]] * ([[r/2^l]] [[alpha < Beta]])^-1 
		 * = [[z/2^l - r/2^l - (alpha <= beta)]]
		 */
		if(isDGK)
		{
			result = DGKOperations.subtract(pubKey, zdiv2L, DGKOperations.encrypt(pubKey, r.divide(powL)));
			//System.out.println("z-r/2^l: " + DGKOperations.decrypt(pubKey, privKey, result));
			//System.out.println("P2 (beta < alpha): " + DGKOperations.decrypt(pubKey, privKey, alpha_lt_beta));
			result = DGKOperations.subtract(pubKey, zdiv2L, alpha_lt_beta);
			//System.out.println("FINAL result: " + DGKOperations.decrypt(pubKey, privKey, result));
		}
		else
		{
           result = PaillierCipher.subtract(zdiv2L, PaillierCipher.encrypt(r.divide(powL), pk), pk);
           //System.out.println("z-r/2^l: " + PaillierCipher.decrypt(result, sk));
           //System.out.println("P2 (beta < alpha): " + PaillierCipher.decrypt(alpha_lt_beta, sk));
           result = PaillierCipher.subtract(zdiv2L, alpha_lt_beta, pk);
           //System.out.println("FINAL result: " + PaillierCipher.decrypt(result, sk));
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
		BigInteger [] C = null;
		BigInteger [] Encrypted_Y = null;
		int deltaB;
		int answer;
		Object in = null;

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
				XOR[i] = DGKOperations.subtract(pubKey, pubKey.ONE(), Encrypted_Y[i]);
			}
		}
		
		// Step 3A: delta A is computed on initialization, it is 0 or 1.
		// Step 3B: Collect index of all index where x_i = GammaA
		ArrayList <Integer> ListofGammaA = new ArrayList<>();
		for (int i = 0; i < Encrypted_Y.length + 1; i++)
		{
			if (NTL.bit(x, i) == deltaA)
			{
				ListofGammaA.add(i);
			}
		}

		// Step 4A: Generate C_i, see c_{-1} to test for equality!
		// C_{-1} = C_i[yBits], will be computed at the end...
		C = new BigInteger [Encrypted_Y.length + 1];
		
		BigInteger product = pubKey.ZERO();
		for (int i = 0; i < Encrypted_Y.length; i++)
		{
			// Goes from yBits - 1 to 0
			C[Encrypted_Y.length - 1 - i] = product;
			product = DGKOperations.add(pubKey, product, XOR[i]);
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
				minus [i] = DGKOperations.subtract(pubKey, pubKey.ONE(), Encrypted_Y[i]);
			}
		}
		
		for (int i = 0; i < Encrypted_Y.length; i++)
		{
			if (deltaA == 0)
			{
				// Step 4 = [1] - [y_i bit] + [c_i]
				C[i] = DGKOperations.add(pubKey, C[i], minus[Encrypted_Y.length - 1 - i]);
			}
			else
			{
				// Step 4 = [y_i] + [c_i]
				C[i]= DGKOperations.add(pubKey, C[i], Encrypted_Y[Encrypted_Y.length - 1 - i]);
			}
		}
		
		//This is c_{-1}
		C[Encrypted_Y.length] = DGKOperations.sum(pubKey, XOR);
		C[Encrypted_Y.length] = DGKOperations.add(pubKey, C[Encrypted_Y.length], DGKOperations.encrypt(pubKey, deltaA));

		// Step 5: Apply the Blinding to C_i and send it to Bob
		for (int i = 0; i < Encrypted_Y.length; i++)
		{
			// if i is NOT in L, just place a random NON-ZERO
			if(!ListofGammaA.contains(i))
			{
				C[Encrypted_Y.length - 1 - i] = DGKOperations.encrypt(pubKey, rnd.nextInt(pubKey.l) + 1);
			}
		}
		// Blind and Shuffle bits!
		C = shuffle_bits(C);
		for (int i = 0; i < C.length; i++)
		{
			C[i] = DGKOperations.multiply(pubKey, C[i], rnd.nextInt(pubKey.l) + 1);
		}
		toBob.writeObject(C);
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
		BigInteger alpha_lt_beta = null;
		BigInteger z = null;
		BigInteger zeta_one = null;
		BigInteger zeta_two = null;
		BigInteger zdiv2L =  null;
		BigInteger result = null;
		Object bob = null;
		BigInteger r = null;
		BigInteger powL = null;

		// Step 1: 0 <= r < N
		// Pick Number of l + 1 + sigma bits
		// Considering DGK is an option, just stick with size of Zu
		
		// THIS IS THE ONLY DIFFERENCE FROM PROTOCOL 2 THAT IT CAN OVERFLOW
		if (isDGK)
		{
			powL = BigInteger.valueOf(exponent(2, pubKey.l - 2));
			r = NTL.RandomBnd(pubKey.u);
		}
		else
		{
			powL = BigInteger.valueOf(exponent(2, pubKey.l));
			r = NTL.RandomBnd(pk.n);
		}
		
		/*
		 * Step 2: Alice computes [[z]] = [[x - y + 2^l + r]]
		 * Send Z to Bob
		 * [[x + 2^l + r]]
		 * [[z]] = [[x - y + 2^l + r]]
		 */
		if (isDGK)
		{
			z = DGKOperations.add(pubKey, x, DGKOperations.encrypt(pubKey, r.add(powL).mod(pubKey.bigU)));
			z = DGKOperations.subtract(pubKey, z, y);
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
        //System.out.println("Protocol 2 alphaZZ: " + alphaZZ);
        //System.out.println("Protocol 3 Result: " + x_leq_y);
    	
		// Step 5: Bob sends z/2^l and GammaB 
		bob = fromBob.readObject();
		if (bob instanceof BigInteger)
		{
			zeta_one = (BigInteger) bob;
		}
		else
		{
			throw new IllegalArgumentException("Protocol 2, Step 5: BigInteger not found!");
		}
		
		bob = fromBob.readObject();
		if (bob instanceof BigInteger)
		{
			zeta_two = (BigInteger) bob;
		}
		else
		{
			throw new IllegalArgumentException("Protocol 2, Step 5: BigInteger not found!");
		}
		
		if(isDGK)
		{
			if(r.compareTo(pubKey.bigU.divide(new BigInteger("2"))) == 0)
			{
				zdiv2L = zeta_one;
			}
			else
			{
				zdiv2L = zeta_two;	
			}	
		}
		else
		{
			if(r.compareTo(pk.n.subtract(BigInteger.ONE).divide(new BigInteger("2"))) == 0)
			{
				zdiv2L = zeta_one;
			}
			else
			{
				zdiv2L = zeta_two;	
			}
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
    	
    	if (isDGK)
    	{
			if(deltaA == 1)
			{
				alpha_lt_beta = DGKOperations.encrypt(pubKey, deltaB);
			}
			else
			{
				alpha_lt_beta = DGKOperations.encrypt(pubKey, 1 - deltaB);
			}
    	}
    	else
    	{
            if(deltaA == 1)
            {
            	alpha_lt_beta = PaillierCipher.encrypt(deltaB, pk);
            }
            else
            {
            	alpha_lt_beta = PaillierCipher.encrypt(1 - deltaB, pk);
            }
    	}

		/*
		 * Step 7, Alice Computes [[x <= y]]
		 * = [[z/2^l]] * ([[r/2^l]] [[alpha < Beta]])^-1 
		 * = [[z/2^l - r/2^l - (alpha <= beta)]]
		 */
		if(isDGK)
		{
			result = DGKOperations.subtract(pubKey, zdiv2L, DGKOperations.encrypt(pubKey, r.divide(powL)));
			//System.out.println("z-r/2^l: " + DGKOperations.decrypt(pubKey, privKey, result));
			//System.out.println("P2 (beta < alpha): " + DGKOperations.decrypt(pubKey, privKey, alpha_lt_beta));
			result = DGKOperations.subtract(pubKey, zdiv2L, alpha_lt_beta);
			//System.out.println("FINAL result: " + DGKOperations.decrypt(pubKey, privKey, result));
		}
		else
		{
           result = PaillierCipher.subtract(zdiv2L, PaillierCipher.encrypt(r.divide(powL), pk), pk);
           //System.out.println("z-r/2^l: " + PaillierCipher.decrypt(result, sk));
           //System.out.println("P2 (beta < alpha): " + PaillierCipher.decrypt(alpha_lt_beta, sk));
           result = PaillierCipher.subtract(zdiv2L, alpha_lt_beta, pk);
           //System.out.println("FINAL result: " + PaillierCipher.decrypt(result, sk));
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
	
	public int Modified_Protocol3(BigInteger r)
			throws ClassNotFoundException, IOException
	{
		return Modified_Protocol3(r.mod(BigInteger.valueOf(exponent(2, pubKey.l))), r, rnd.nextInt(2));
	}
	
	// Modified Protocol 3 for Protocol 4
	// This should mostly use ONLY DGK stuff!
	private int Modified_Protocol3(BigInteger alpha, BigInteger r, int _deltaA) 
			throws ClassNotFoundException, IOException
	{
		int deltaA;
		if(_deltaA == 0 || _deltaA == 1)
		{			
			deltaA = _deltaA;
		}
		else
		{
			deltaA = rnd.nextInt(2);
		}
		int answer = -1;
		Object in = null;
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
		if(r.compareTo(pk.n.subtract(BigInteger.ONE).divide(new BigInteger("2"))) == -1)
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
				encAlphaXORBeta[i] = DGKOperations.subtract(pubKey, pubKey.ONE(), beta_bits[i]);				
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
				w[i] = DGKOperations.subtract(pubKey, encAlphaXORBeta[i], d);
			}
		}
		
		// Step F: See optimization...
		for (int i = 0; i < beta_bits.length;i++)
		{
			if(NTL.bit(alpha_hat, i) == NTL.bit(alpha, i))
			{
				w[i] = DGKOperations.multiply(pubKey, w[i], pubKey.l);	
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
			product = DGKOperations.sum(pubKey, w, beta_bits.length - 1 - i);
			C[beta_bits.length - 1 - i] = DGKOperations.multiply(pubKey, product, 3);
			// C_i += s
			C[beta_bits.length - 1 - i] = DGKOperations.add(pubKey, S, C[beta_bits.length - 1 - i]);
			
			// t = alpha_i - beta_i
			temp[i] = DGKOperations.subtract(pubKey, DGKOperations.encrypt(pubKey, NTL.bit(alpha, i)), beta_bits[i]);
			exponent = NTL.bit(alpha_hat, i) - NTL.bit(alpha, i);
			// t = d^{a - a}
			temp[i] = DGKOperations.add(pubKey, temp[i], DGKOperations.multiply(pubKey, d, exponent));
		}

		// Combine terms!
		for(int i = 0; i < beta_bits.length;i++)
		{
			C[i] = DGKOperations.add(pubKey, C[i], temp[i]);
		}
		
		//This is c_{-1}
		C[beta_bits.length] = DGKOperations.sum(pubKey, encAlphaXORBeta);
		C[beta_bits.length] = DGKOperations.add(pubKey, C[beta_bits.length], DGKOperations.encrypt(pubKey, deltaA));

		// Step I: SHUFFLE BITS AND BLIND WITH EXPONENT
		C = shuffle_bits(C);
		for (int i = 0; i < C.length; i++)
		{
			C[i] = DGKOperations.multiply(pubKey, C[i], rnd.nextInt(pubKey.l) + 1);
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
		Object in = null;
		BigInteger answer = null;
		BigInteger c = null;
		BigInteger z = null;
		BigInteger r = null;
		
		// Step 1
		if(isDGK)
		{
			r = NTL.RandomBnd(log2((int) (pubKey.u - 1)/2));
			z = DGKOperations.add(pubKey, x, DGKOperations.encrypt(pubKey, r));
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
			answer = DGKOperations.subtract(pubKey, c, DGKOperations.encrypt(pubKey, r.divide(BigInteger.valueOf(d))));
			answer = DGKOperations.subtract(pubKey, answer, DGKOperations.encrypt(pubKey, t));
			answer = DGKOperations.add(pubKey, answer, DGKOperations.encrypt(pubKey, 1));
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
			System.out.println("answer: " + DGKOperations.decrypt(privKey, answer));	
		}
		else
		{
			System.out.println("answer: " + PaillierCipher.decrypt(answer, sk));	
		}
		return answer;
	}
	
	public BigInteger multiplication(BigInteger x, BigInteger y) 
			throws IOException, ClassNotFoundException
	{
		Object in = null;
		BigInteger x_prime = null;
		BigInteger y_prime = null;
		BigInteger a = null;
		BigInteger b = null;
		BigInteger result = null;
		
		// Step 1
		if(isDGK)
		{
			a = NTL.RandomBnd(pubKey.bigU.subtract(BigInteger.ONE));
			b = NTL.RandomBnd(pubKey.bigU.subtract(BigInteger.ONE));
			x_prime = DGKOperations.add(pubKey, DGKOperations.encrypt(pubKey, a), x);
			y_prime = DGKOperations.add(pubKey, DGKOperations.encrypt(pubKey, b), y);
		}
		else
		{
			a = NTL.RandomBnd(pk.n.subtract(BigInteger.ONE));
			b = NTL.RandomBnd(pk.n.subtract(BigInteger.ONE));	
			x_prime = PaillierCipher.add(x, PaillierCipher.encrypt(a, pk), pk);
			y_prime = PaillierCipher.add(y, PaillierCipher.encrypt(b, pk), pk);
		}
		toBob.writeObject(x_prime);
		toBob.writeObject(y_prime);
		toBob.flush();
		
		// Step 2
		
		// Step 3
		in = fromBob.readObject();
		if (in instanceof BigInteger)
		{
			result = (BigInteger) in;
			if(isDGK)
			{
				result = DGKOperations.subtract(pubKey, DGKOperations.multiply(pubKey, x, b), result);
				result = DGKOperations.subtract(pubKey, DGKOperations.multiply(pubKey, y, a), result);
				result = DGKOperations.subtract(pubKey, DGKOperations.encrypt(pubKey, a.multiply(b)), result);	
			}
			else
			{
				result = PaillierCipher.subtract(result, PaillierCipher.multiply(x, b, pk), pk);
				result = PaillierCipher.subtract(result, PaillierCipher.multiply(y, a, pk), pk);
				result = PaillierCipher.subtract(result, PaillierCipher.encrypt(a.multiply(b), pk), pk);
			}
		}
		else
		{
			throw new IllegalArgumentException("");
		}
		return result;
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
		Pair result = getMinMax(input, input.size());
		
		// Kill the Process listening for more Protocol 2.
		// IF USING TO SORT...DO NOT DIE YET!
		if(isNotSorting)
		{
			toBob.writeBoolean(false);
		}
		return result;
	}
	
	// https://www.geeksforgeeks.org/maximum-and-minimum-in-an-array/
	public Pair getMinMax(ArrayList<BigInteger> arr, int n) 
			throws ClassNotFoundException, IOException
	{
		Pair results = new Pair();   
		int i;

		/* If array has even number of elements then 
			    initialize the first two elements as minimum and 
			    maximum */
		//Protocol 2 works as intended here...
		if (n % 2 == 0)
		{
			toBob.writeBoolean(true);
			if (Protocol2(arr.get(0), arr.get(1)) == 0)     
			{
				results.min = arr.get(0);
				results.max = arr.get(1);
				//System.err.println("Start with 0");
			}
			else
			{
				results.max = arr.get(0);
				results.min = arr.get(1);
				//System.err.println("Start with 1");
			}
			i = 2;  /* set the starting index for loop */
		}

		/* If array has odd number of elements then 
			    initialize the first element as minimum and 
			    maximum */
		else
		{
			results.min = arr.get(0);
			results.max = arr.get(0);
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

		while (i < n - 1)
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

			if (Protocol2(arr.get(i), arr.get(i+1)) != 0)
			{
				toBob.writeBoolean(true);
				if((Protocol2(arr.get(i), results.max)) != 0)
				{
					//System.out.println("Protocol 2: " + a + " max: " + Paillier.decrypt(results.max, server.sk) +" arr(i): " + Paillier.decrypt(arr[i], server.sk));
					results.max = arr.get(i);
				}
				toBob.writeBoolean(true);
				if((Protocol2(arr.get(i + 1), results.min)) != 1)
				{
					//System.out.println("Protocol 2: " + b + " arr(i+1): " + Paillier.decrypt(arr[i+1], server.sk) +" min: " + Paillier.decrypt(results.min, server.sk));
					results.min = arr.get(i + 1);
				}
				//System.out.println("(top) new min: " + Paillier.decrypt(results.min, server.sk) +" new max: " + Paillier.decrypt(results.max, server.sk) + " given i: " + i + " and ans: " + answer);
			} 
			else        
			{
				toBob.writeBoolean(true);
				if ((Protocol2(arr.get(i + 1), results.max)) != 0) 
				{
					//System.out.println("Protocol 2: " + a + " max: " + Paillier.decrypt(results.max, server.sk) +" arr(i+1): " + Paillier.decrypt(arr[i+1], server.sk));
					results.max = arr.get(i + 1);
				}
				toBob.writeBoolean(true);
				if ((Protocol2(arr.get(i), results.min)) != 1)
				{
					//System.out.println("Protocol 2: " + b + " arr(i): " + Paillier.decrypt(arr[i], server.sk) +" min: " + Paillier.decrypt(results.min, server.sk));
					results.min = arr.get(i);
				}
				//System.out.println("Protocol 2 parts: a, " + a + " b, " + b);
				//System.out.println("(bot) new min: " + Paillier.decrypt(results.min, server.sk) +" new max: " + Paillier.decrypt(results.max, server.sk) + " given i: " + i + " and ans: " + answer);
			}
			i += 2; /* Increment the index by 2 as two elements are processed in loop */
		}
		return results;
	}

	// https://www.geeksforgeeks.org/maximum-and-minimum-in-an-array/
	public Pair getMinMax(BigInteger [] arr, int n) 
			throws ClassNotFoundException, IOException
	{
		Pair results = new Pair();   
		int i;

		/* If array has even number of elements then 
		    initialize the first two elements as minimum and 
		    maximum */
		//Protocol 2 works as intended here...
		if (n % 2 == 0)
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
		
		while (i < n - 1)
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
			
			if (Protocol2(arr[i], arr[i + 1]) != 0)
			{
				toBob.writeBoolean(true);
				if((Protocol2(arr[i], results.max)) != 0)
				{
					//System.out.println("Protocol 2: " + a + " max: " + Paillier.decrypt(results.max, server.sk) +" arr(i): " + Paillier.decrypt(arr[i], server.sk));
					results.max = arr[i];
				}
				toBob.writeBoolean(true);
				if((Protocol2(arr[i + 1], results.min)) != 1)
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

	// To sort an array of encrypted numbers
	public void sortArray() 
			throws ClassNotFoundException, IOException
	{
		System.out.println("Sorting Initialized!");
		if(toSort == null)
		{
			sortedArray = null;
		}
		if(toSort.length == 1 || toSort.length == 0)
		{
			sortedArray = toSort;
		}
		else if (toSort.length == 2)
		{
			ArrayList<BigInteger> Sort = new ArrayList<BigInteger>(Arrays.asList(toSort));
			Pair result = findExtrema(Sort, true);
			sortedArray = new BigInteger[2];
			sortedArray[0] = result.min;
			sortedArray[1] = result.max;
			toBob.writeBoolean(false);
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
				sortedArray = toSort;
				this.doMergeSort(0, sortedArray.length - 1);
				break;
		        
			case QUICK_SORT:	
				sortedArray = toSort;
				this.sort(sortedArray, 0, sortedArray.length - 1);
				break;
				
			case BUBBLE_SORT:
				sortedArray = toSort;
				this.bubbleSort(sortedArray);
			default:
				break;
		}
        // Time to end Bob's while loop for Protocol2()
        toBob.writeBoolean(false);
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
				System.out.print(DGKOperations.decrypt(privKey, bits[i]) + ",");
			}
			else
			{
				System.out.print("NULL,");
			}
		}
		System.out.println("");
	}
	
	private void getkey() throws ClassNotFoundException, IOException
	{
		Object in;
		in = fromBob.readObject();
		if (in instanceof DGKPrivateKey)
		{
			privKey = (DGKPrivateKey) in;
		}
		else
		{
			throw new IllegalArgumentException("Invalid, did not receive DGK Private Key!");
		}
		in = fromBob.readObject();
		if (in instanceof PaillierPrivateKey)
		{
			sk = (PaillierPrivateKey) in;
		}
		else
		{
			throw new IllegalArgumentException("Invalid, did not receive Paillier Private Key!");
		}
	}
	
	// Used to shuffle the encrypted bits
	private static BigInteger [] shuffle_bits(BigInteger [] array)
	{
		Random rgen = new Random();  // Random number generator
		for (int i = 0; i < array.length; i++) 
		{
			int randomPosition = rgen.nextInt(array.length);
		    BigInteger temp = array[i];
		    array[i] = array[randomPosition];
		    array[randomPosition] = temp;
		}
		return array;
	}

	// Below are all supported sorting techniques!
    // ----------------Bubble Sort------------------------------
	private void bubbleSort(BigInteger [] arr) 
			throws IOException, ClassNotFoundException
	{
		int n = arr.length;
		for (int i = 0; i < n - 1; i++)
		{
			for (int j = 0; j < n - i - 1; j++)
			{
				toBob.writeBoolean(true);
				if (this.Protocol2(arr[j], arr[j+1]) == 0)
				{
					// swap temp and arr[i]
					BigInteger temp = arr[j];
					arr[j] = arr[j + 1];
					arr[j + 1] = temp;
				}
			}
		}
	}
	
	// --------------Quick Sort---------------------
	// Quick Sort
	/* This function takes last element as pivot,
	    places the pivot element at its correct
	    position in sorted array, and places all
	    smaller (smaller than pivot) to left of
	    pivot and all greater elements to right
	    of pivot */
	private int partition(BigInteger arr[], int low, int high)
			throws ClassNotFoundException, IOException
	{
		BigInteger pivot = arr[high]; 
		int i = low - 1; // index of smaller element
		for (int j = low; j < high; j++)
		{
			// If current element is smaller than or
			// equal to pivot
			//if (arr[j] <= pivot)
			toBob.writeBoolean(true);
			if(this.Protocol2(arr[j], pivot) != 1)
			{
				++i;
				// swap arr[i] and arr[j]
				BigInteger temp = arr[i];
				arr[i] = arr[j];
				arr[j] = temp;
			}
		}
		// swap arr[i+1] and arr[high] (or pivot)
		BigInteger temp = arr[i + 1];
		arr[i + 1] = arr[high];
		arr[high] = temp;
		return i + 1;
	}


	/* 
	 * The main function that implements QuickSort()
	 * arr[] --> Array to be sorted,
	 * low  --> Starting index,
	 * high  --> Ending index 
	 */
	private void sort(BigInteger arr[], int low, int high)
			throws ClassNotFoundException, IOException
	{
		if (low < high)
		{
			/* pi is partitioning index, arr[pi] is 
	           now at right place */
			int pi = partition(arr, low, high);

			// Recursively sort elements before
			// partition and after partition
			sort(arr, low, pi - 1);
			sort(arr, pi + 1, high);
		}
	}
	
	// --------------Merge Sort---------------------

	void doMergeSort(int lowerIndex, int higherIndex) 
			throws ClassNotFoundException, IOException
	{
		if (lowerIndex < higherIndex)
		{
			int middle = lowerIndex + (higherIndex - lowerIndex) / 2;
			// Below step sorts the left side of the array
			doMergeSort(lowerIndex, middle);
			// Below step sorts the right side of the array
			doMergeSort(middle + 1, higherIndex);
			// Now merge both sides
			mergeParts(lowerIndex, middle, higherIndex);
		}
	}

	private void mergeParts(int lowerIndex, int middle, int higherIndex)
			throws ClassNotFoundException, IOException
	{
		int i = lowerIndex;
		int j = middle + 1;
		int k = lowerIndex;

		tempBigMerg = Arrays.copyOf(sortedArray, sortedArray.length);
		while (i <= middle && j <= higherIndex)
		{
			toBob.writeBoolean(true);
			if ((this.Protocol2(tempBigMerg[i], tempBigMerg[j])) != 1)
			{
				//System.out.println("answer: " + answer + " x="+Paillier.decrypt(tempBigMerg[i], server.sk) + " y="+Paillier.decrypt(tempBigMerg[j], server.sk));
				sortedArray[k] = tempBigMerg[i];
				++i;
			}
			else
			{
				sortedArray[k] = tempBigMerg[j];
				++j;
			}
			++k;
		}
		while (i <= middle)
		{
			sortedArray[k] = tempBigMerg[i];
			++k;
			++i;
		}
	}
	
	public boolean match() throws IOException
	{
		toBob.writeObject(pk);
		toBob.flush();
		toBob.writeObject(pubKey);
		toBob.flush();
		return fromBob.readBoolean();
	}

	public void run() 
	{
		try
		{
			sortArray();
		}
		catch (ClassNotFoundException | IOException e) 
		{
			e.printStackTrace();
		}
	}
}
