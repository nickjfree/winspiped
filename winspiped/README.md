winspiped
======

winspiped visual studio project

Orignal spiped is at:
> https://github.com/Tarsnap/spiped

Works the the same way as the orignal spiped with only slight difference.  


Building
--------

  Requirements 
  
  1. Visual studio 2013 1024 or 2015.
  2. Prebuild openssl library on windows. x86 or x64. 
  3. Actvieperl to build openssl on windows.
  
 
Example usage
-------------

on a server
    assuming you have squid running on you linux machine.

    dd if=/dev/urandom bs=32 count=1 of=keyfile
    spiped -d -s '[0.0.0.0]:8080' -t '[127.0.0.1]:3128' -k keyfile
    
    or  
    winspiped -d -s '[0.0.0.0]:8080' -t '[127.0.0.1]:3128' -k keyfile
        
    if you are running spiped on windows

on a client and after copying keyfile to the local system, run

    winspiped -e -s '[127.0.0.1]:55555' -t  $YOUR_SERVER_ADDRESS:8080  -k  keyfile

You know what i mean. Or this is not the right place for you.
