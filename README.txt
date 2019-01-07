This is a module created from the SST REU 2017 project.

This module contains a function Android and Java support for
- Paillier
- DGK
- DGK Comparison Protocols (NOTE: PROTOCOL 4 IS NOT COMPLETE. May complete later)
- Encrypted Integer Divison.

Papers Cited:
Encrypted Integer Division by Thjis Veugen
Improving the DGK comparison protocol by Thjis Veugen

Context:
In the case of Comparison Protocols. Alice has [[x]] and [[y]], two DGK or Paillier encrypted values. Bob has the DGK and/or Paillier Private Key.
For Division, Alice has [x] and d. Bob has d and Private Key. Alice would obtain [x/d] at the end of division protocol.

By default...the Phone/Server will sort encrypted numbers. Note that comparing two encrypted numbers can take abotu 1.5 seconds on average.

How to use:
The Phone interface should be pretty straight forward. If you press Alice. Random numbers will be generated and printed. It will connect to Bob 
on the SocialistMillionaire Server and sort the array.

Customizations:
1- Note that Bob DOES close the socket and I/O streams! You may want to avoid this!
2- By default Alice will use MergeSort to sort encrypted arrays. QuickSort is about the same speed.
3- PLEASE BE VERY CAREFUL ABOUT THE SERVER SETTINGS. CURRENTLY IT IS SET TO ALICE MODE AND DGK MODE OFF. This can be changed by changing the code or through the shell!
4- How to use each Protocol...If Alice wants to use a method, Bob must call the correct method for this to work correctly...

Alice			Bob
max/min			Protocol2()
sortArray		Protocol2()
divide			divide()
Protocol2()		Protocol2()
Protocol3() 		Protocol3()

Please feel free to review the SST REU 2017 project which uses this module to get minimum distance and divide encrypted numbers.