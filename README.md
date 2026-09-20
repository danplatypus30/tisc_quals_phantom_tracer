# Phantom Tracer
TISC@DEF CON SG
### Description
We deployed our Phantom Tracer system to hunt down a new threat in the digital infrastructure, but intelligence confirms our worst fears: the phantom has compromised the tracer and taken control. We need to act fast and regain control of it before the phantom disappears completely. Ironically, the security flaws we never patched when prioritising speed might be our only way back in. The hunt has become a race against time.

nc chals[.]tisc-dc26.csit-events.sg 31629

Attached files: <br>
libc.so <br>
phantom_tracer <br>

## Intro

I decided to do a writuep for this heap pwn challenge, hopefully it helps anyone who wants to learn pwn without blindly clanking :)

Setup:
Windows Laptop, Ubuntu WSL, Ghidra, pwndbg

## Writeup

### 1. Run the program

See how it works. 

<img src="images/run1.png" alt="run1" style="height:200px;"> 

<img src="images/run2.png" alt="run2" style="height:50px;"> 

<img src="images/run3.png" alt="run3" style="height:50px;"> 

<img src="images/run4.png" alt="run4" style="height:50px;"> 

<img src="images/run5.png" alt="run5" style="height:50px;"> 

4 commands, since its a heap pwn challenge, we likely know: <br>
1 - create heap<br>
2 - modify data at heap<br>
3 - free heap<br>
4 - read data at heap<br>

There likely has to be some overflow vulnerability to leak some data.

### 2. Ghidra

Pull up the program in Ghidra, it should open the `main()` function automatically. <br>
I modified some variable names: `new_heap`, `total_size`, `input`, `index`, `curr_index`. <br>
These can be derived from functions like `scanf`, the increments after each loop and the output text. <br>

input == 4, read data at heap

<img src="images/ghidra1.png" alt="ghidra1" style="height:80px;"> 

This reads the data stored in the heap at that index. <br>
`write(1, address of start of that node, size of that node)`
<br>

input == 3, free heap

<img src="images/ghidra2.png" alt="ghidra2" style="height:100px;"> 

This frees the specified node.<br>
Note that the data in that node is not cleared.
<br>

input == 1, create heap

<img src="images/ghidra3.png" alt="ghidra3" style="height:250px;"> 

There can be max 9 nodes.<br>
"Signal strength" refers to size of the new node, max 1080<br>
It then `malloc`s the size, then points the next node at this address.<br>
Then increments total size.
<br>

input == 2, modify data at heap

<img src="images/ghidra4.png" alt="ghidra4" style="height:100px;"> 

Similar to the write above<br>
`read(1, address of start of that node, size of that node)`

<br>

To put data in the node, we need to create -> modify.<br>
Free-ing does not clear the data. Vulnerable.<br>
`chunks` and `sizes` are probably a bunch of pointers, each new node is `malloc`-ed and each pointer points to the allocated memory in the heap.





