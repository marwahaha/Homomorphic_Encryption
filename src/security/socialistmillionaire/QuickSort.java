package security.socialistmillionaire;

import java.io.IOException;
import java.math.BigInteger;

/*
 * Code Taken from:
 * https://www.geeksforgeeks.org/quick-sort/
 * 
 * This has been fused with Protocol 2/3 for DGK comparison to sort 
 * encrypted DGK or Paillier Numbers
 */
public class QuickSort
{
	private alice Alice;
	private BigInteger [] arr;
	private int length;

	public QuickSort(int [] arr)
	{
		this.sort(arr, 0, arr.length - 1);
	}

	public QuickSort(long [] arr)
	{
		this.sort(arr, 0, arr.length - 1);
	}
	
	public QuickSort(BigInteger [] _arr, alice Yujia)
	{
		Alice = Yujia;
		arr = _arr;
		length = arr.length;
	}

	public BigInteger[] getSortedArray()
	{
		return arr;
	}
	
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
		int i = (low - 1); // index of smaller element
		for (int j = low; j < high; j++)
		{
			// If current element is smaller than or
			// equal to pivot
			//if (arr[j] <= pivot)
			Alice.sendRequest();
			if(Alice.Protocol2(arr[j], pivot) != 1)
			{
				i++;
				// swap arr[i] and arr[j]
				BigInteger temp = arr[i];
				arr[i] = arr[j];
				arr[j] = temp;
			}
		}

		// swap arr[i+1] and arr[high] (or pivot)
		BigInteger temp = arr[i+1];
		arr[i+1] = arr[high];
		arr[high] = temp;

		return i + 1;
	}


	/* 
	 * The main function that implements QuickSort()
	 * arr[] --> Array to be sorted,
	 * low  --> Starting index,
	 * high  --> Ending index 
	 */
	void sort(BigInteger arr[], int low, int high)
			throws ClassNotFoundException, IOException
	{
		if (low < high)
		{
			/* pi is partitioning index, arr[pi] is 
           now at right place */
			int pi = partition(arr, low, high);

			// Recursively sort elements before
			// partition and after partition
			sort(arr, low, pi-1);
			sort(arr, pi+1, high);
		}
	}

	//======================PLAIN INTEGER=====================================================
	private void sort(int arr[], int low, int high)
	{
		if (low < high)
		{
            /* pi is partitioning index, arr[pi] is
              now at right place */
			int pi = partition(arr, low, high);

			// Recursively sort elements before
			// partition and after partition
			sort(arr, low, pi-1);
			sort(arr, pi+1, high);
		}
	}

	private int partition(int arr[], int low, int high)
	{
		int pivot = arr[high];
		int i = (low-1); // index of smaller element
		for (int j=low; j<high; j++)
		{
			// If current element is smaller than or
			// equal to pivot
			if (arr[j] <= pivot)
			{
				i++;

				// swap arr[i] and arr[j]
				int temp = arr[i];
				arr[i] = arr[j];
				arr[j] = temp;
			}
		}

		// swap arr[i+1] and arr[high] (or pivot)
		int temp = arr[i+1];
		arr[i+1] = arr[high];
		arr[high] = temp;

		return i+1;
	}

	//======================PLAIN INTEGER=====================================================
	private void sort(long arr[], int low, int high)
	{
		if (low < high)
		{
            /* pi is partitioning index, arr[pi] is
              now at right place */
			int pi = partition(arr, low, high);

			// Recursively sort elements before
			// partition and after partition
			sort(arr, low, pi-1);
			sort(arr, pi+1, high);
		}
	}

	private int partition(long arr[], int low, int high)
	{
		long pivot = arr[high];
		int i = (low-1); // index of smaller element
		for (int j=low; j<high; j++)
		{
			// If current element is smaller than or
			// equal to pivot
			if (arr[j] <= pivot)
			{
				i++;

				// swap arr[i] and arr[j]
				long temp = arr[i];
				arr[i] = arr[j];
				arr[j] = temp;
			}
		}

		// swap arr[i+1] and arr[high] (or pivot)
		long temp = arr[i+1];
		arr[i+1] = arr[high];
		arr[high] = temp;

		return i+1;
	}

	public void run() 
	{
		try 
		{
			this.sort(arr, 0, length - 1);
		}
		catch (ClassNotFoundException | IOException e)
		{
			e.printStackTrace();
		}
	}
}
