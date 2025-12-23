# APC_base-Process-Injection-Tool
This tool is a Process Injection Tool ( 32-bit ) using the APC technique where instead of creating new Threads  ( which are more likely to be flagged by EDR and AVs ) , it Hijacks existing thread and Inject the code in its queue..... It is not applicable for 64-bit architectured windows as Irvine32 Library is used in it as it is for 32-bit architecture and if I want to make it 64 bit than Irvine64 will be used and whole code has to be changed as 64-bit architecture has registers RAX,RBX,RCX etc. unlike 32-bit architectured windows that has EAX,EAB,ECX etc. registers 

This project was made just for educational purpose to demonstrate working of APC ( Asynchronous Procedure Call ) attack as it is stealthier than simple Process inejction ... In my project , to evade signature obfuscation , i have implemented XOR encryption with the malware file so that its signature gets changes and it become able to bypass static analysis of AntiViruses and EDRs . My tool uses 2 modes (simple malware injection , encrypted malware injection ) . 

STEPS TO USE IT :

1) First of all install VISUAL STUDIO IDE in your computer. It can be downloaded from https://visualstudio.microsoft.com/
2) Download Irvine32 library from github repo https://github.com/Eazybright/Irvine32
3) Configure Visual studio for your project and configure Irvine32 library 
4) Now U can take a look to this youtube video for configuring Irvinelibrary : https://youtu.be/4XH_iEehGZ0?si=KEcz2RCsm3Av1cKk
5) After completing all that stuff , get this code and paste it in your project .
6) As this encryption tool is separate tool and injection tool is separate so u have to create separate projects in visual studio .
7) Now Copy-Paste these codes in your project files in visual studio and compile and start injection ...

NOTE : This is online compatible to 32-bit windows . If you tried to inject code to 64-bit windows via this tool , it will likely crash your Program in which you have injected.

