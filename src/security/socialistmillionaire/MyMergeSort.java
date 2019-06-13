package security.socialistmillionaire;

import java.io.IOException;
import java.math.BigInteger;

// Created by Andrew on 7/20/2017.
// Code originally from:
// https://www.geeksforgeeks.org/merge-sort/

import java.util.Arrays;

public class MyMergeSort
{
	// Long
    public long [] array;
    public long [] tempMergArr;
    
    // BigInteger...Encrypted!
    private BigInteger [] bigArray = null;
    private BigInteger [] tempBigMerg = null;
    private alice Alice = null;
    private int length;
    
    public MyMergeSort(long arr [])
    {
    	array = arr;
    	length = arr.length;
    	tempMergArr = new long[length];
    }
    
    // Fuse this with Protocol 2/3 from sorting!
    public MyMergeSort(BigInteger [] input, alice _sorting)
    {
    	bigArray = input;
    	length = input.length;
    	tempBigMerg = new BigInteger[length];
    	Alice = _sorting;
    }
    
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
        
        // For encrypted Numbers
        if (bigArray != null)
        {
            tempBigMerg = Arrays.copyOf(bigArray, bigArray.length);
            while (i <= middle && j <= higherIndex)
            {
            	// Use DGK Comparison Protocol Here!
            	// int answer = -1;
                Alice.sendRequest();
                if ((Alice.Protocol2(tempBigMerg[i], tempBigMerg[j])) != 1)
                {
                	//System.out.println("answer: " + answer + " x="+Paillier.decrypt(tempBigMerg[i], server.sk) + " y="+Paillier.decrypt(tempBigMerg[j], server.sk));
                    bigArray[k] = tempBigMerg[i];
                    i++;
                }
                else
                {
                    bigArray[k] = tempBigMerg[j];
                    j++;
                }
                k++;
            }
            while (i <= middle)
            {
                bigArray[k] = tempBigMerg[i];
                k++;
                i++;
            }
        }
        // Regular Merge Sort
        else 
        {
        	tempMergArr = Arrays.copyOf(array, array.length);
            while (i <= middle && j <= higherIndex)
            {
                if (tempMergArr[i] <= tempMergArr[j])
                {
                    array[k] = tempMergArr[i];
                    i++;
                }
                else
                {
                    array[k] = tempMergArr[j];
                    j++;
                }
                k++;
            }
            while (i <= middle)
            {
                array[k] = tempMergArr[i];
                k++;
                i++;
            }	
        }
    }
	
	public BigInteger[] getSortedArray()
	{
		return bigArray;
	}
}