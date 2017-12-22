This post is for [Harekaze Advent Calendar 2017.](https://adventar.org/calendars/2292)

<br>**Introduction**

As I am now working on malware analysis using machine learning in my study group, I have opportunities of playing with PE malware. For extracting all assembly code of the malware itself, I will use brand-new binary parsing/modifying/constructing platform called [LIEF](https://github.com/lief-project/LIEF).

<br>**Goal**

In this post I will try to perform all of assembly code in .text segment. 
In my understanding this section is corresponded to code we usually write (Is that correct?). This assembly code also has addresses of imported Windows APIs. For Windows APIs show potential behaviour of executables, I tried to replace the addresses with Windows APIs, after extracting the assembly.

<br>**LIEF**

LIEF is a cross platform library to parse, modify and construct binary. You can perform not only binary parsing, but change some assembly-level codes with this. In parsing, whilst [pefile](https://github.com/erocarrera/pefile) only parses PE executables, LIEF can parse not only PEs and ELFs, but Mach-O files. Using Python bindings, you can parse all the information using object-style.

<br>**Implementation**

```
import lief

import re

import os
import os.path


def main():


    # Would appreciate if you teach me more sophisticated implementation

    binary_file_name = "output.txt"
    binary = raw_input() # path to target binary

    b = lief.PE.parse(binary)
    txt_section = b.get_section(".text")
    contents = txt_section.content # contents are list [aa, bb, cc] and decimal
    contents_hex = []

    for i in contents:
        binary_one_letter_list = ["x0", "x1", "x2", "x3", "x4", "x5", 
                                  "x6", "x7", "x8", "x9", "xa", "xb", 
                                  "xc", "xd", "xe", "xf"]
        data = str(hex(i)) # decimal->hex->str
        data = re.sub("L", "", data)
        data = re.sub("0x", "x", data)
        for j in binary_one_letter_list:
            if data == j:
                data = re.sub("x", "x0", data) # editing each letter for Capstone 
            else:                              # disas at that time, I tried but not work.
                continue                       # idk why. will investigate later.
        contents_hex.append(data)

    str_contents_hex = "\\".join(contents_hex)

    # getting import address table
    dictionary_of_iat = {}
    for imported_library in b.imports:
        for func in imported_library.entries:
            if not func.is_ordinal:
                dictionary_of_iat[func.name] = hex(func.iat_address)
                        
            else:
                continue

    for k, v in dictionary_of_iat.items():

        address_with_L = str(v)

        print "address_with_L is " + address_with_L

        address_little_endien = "\\\\x" + address_with_L[4] + address_with_L[5] + "\\\\x" + address_with_L[2] + address_with_L[3]

        print "address_little_endien of " + k + " is " + address_little_endien

        # endien checking
        check = str_contents_hex.find(address_little_endien)
        if check == []:
            print "There is no address_little_endien of " + k
            print "Will be abort the procedure of " + k + "\n"
            continue
                

        else:
            print "There is address_little_endien of " + k
            letter = "\\\\" + k
            p = re.compile(address_little_endien)
            str_contents_hex = p.sub(letter, str_contents_hex)


            print "Done replacing address with " + k +"\n"
            continue
                
    with open(binary_file_name, "w") as f:

        f.write(str_contents_hex)

if __name__ == '__main__':
    main()
```

For your information, pefile seems to extract .text assembly code using string version. So if you try to print this you will see bunch of terribly meaningless strings, for its output is just letters same as that appeared when you watch the binary with binary editor.
On the contrary the extracted assembly using LIEF has object version.

Output:
```
...\x74\x24\x18\xd8\xc1\xd8\x05\xb4\xa3\x40\x00\xdd\x5c\x24\x10\x81\x6c\x24\x14\x00\x00\x40\x03\x85\xf6\x0f\LeaveCriticalSection\x01\x00\x00\x8b\x54\x24\x18\xd9\xc0\xc7\x44\x24\x38\x00\x00\x00\x00\x8b\x4c\x24\x40\x85\xc9\x0f...
```
Then I extracted the assembly in text segment codes but I do not know whether this will be good feature for machine learning.

<br>**Conclusion**

To me LIEF is far more convenient than pefile. Somebody said the speed of pefile parsing, so If I have a time I will compare the speed of LIEF with that of pefile.
Honestly, reading official LIEF documents will benefit you more than reading this shitty post for further understanding of LIEF.
With LIEF, building my own symbolic execution tool might be interesting (I remember angr uses pefile to parse the binary). 
If there is a mistake, I would appreciate if you let me know.
