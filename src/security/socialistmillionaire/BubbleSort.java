package security.socialistmillionaire;

import java.io.IOException;
import java.math.BigInteger;

// https://www.geeksforgeeks.org/bubble-sort/
// Java program for implementation of Bubble Sort
public class BubbleSort
{
	// Arrays to Sort
	/*
	private int [] arr;
	private long [] long_arr;
	public BubbleSort(int _arr[])
	{
		arr = _arr;
	}
	
	public BubbleSort(long _arr[])
	{
		long_arr = _arr;
	}
	*/
	
	private BigInteger [] encrypted;
	private alice Alice;
	
	
	public BubbleSort(BigInteger _arr[], alice _Alice)
	{
		encrypted = _arr;
		Alice = _Alice;
	}
	
	protected void bubbleSort() throws ClassNotFoundException, IOException
	{
		bubbleSort(encrypted);
	}
	
	protected void bubbleSort(BigInteger arr[]) 
			throws IOException, ClassNotFoundException
	{
		int n = arr.length;
		for (int i = 0; i < n-1; i++)
		{
			for (int j = 0; j < n-i-1; j++)
			{
				Alice.sendRequest();
				if (Alice.Protocol2(arr[j], arr[j+1]) == 0)
				{
					// swap temp and arr[i]
					BigInteger temp = arr[j];
					arr[j] = arr[j+1];
					arr[j+1] = temp;
				}
			}
		}
	}
	
	protected void bubbleSort(int arr[])
	{
		int n = arr.length;
		for (int i = 0; i < n-1; i++)
		{
			for (int j = 0; j < n-i-1; j++)
			{
				if (arr[j] > arr[j+1])
				{
					// swap temp and arr[i]
					int temp = arr[j];
					arr[j] = arr[j+1];
					arr[j + 1] = temp;
				}
			}
		}
	}
	
	protected void bubbleSort(long arr[])
	{
		int n = arr.length;
		for (int i = 0; i < n-1; i++)
		{
			for (int j = 0; j < n-i-1; j++)
			{
				if (arr[j] > arr[j+1])
				{
					// swap temp and arr[i]
					long temp = arr[j];
					arr[j] = arr[j+1];
					arr[j + 1] = temp;
				}
			}
		}
	}
	
	public BigInteger[] getSortedArray()
	{
		return encrypted;
	}                    
}