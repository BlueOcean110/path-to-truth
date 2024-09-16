# Disobey 2025 hacker badge puzzle

This is a writeup and file repository for the Disobey 2025 nordic hacker event hacker badge puzzle challenge. I really enjoyed this years offering.

This directory includes this spoiler writeup, the unsolved file assets and then the solved files that have been exfiltrated, extracted or decrypted.

If you want to play at home at a later date start with the main level of this path-of-truth repository and then if the additional files are no longer hosted on the internet you can next take the `challenge_files/incident_data.pcapng` and continue from there. `challenge_files/confidential.7z` is another file downloaded from somewhere else...

The rest of this document constains spoilers.

## Spoilers: The puzzle chain
1. Pre-release leaks
  * Monitoring certificate transparency logs
    * kouvostoforensics.com pops up https://crt.sh/?id=14378925139
      * has basic auth, but is really interesting!
2. Twitter
  * Nothing here other than the username
  * Try to find out if that is used anywhere else
3. https://github.com/blueocean110
  * Same avatar
  * Commit message
    * Google translate: `Opera Alcacoon! No need to guess. AES-256-CBC and pbkdf2 are suitable for locking.`
  * key - rsa public key
    * RSA with strange exponent
    * https://github.com/RsaCtfTool/RsaCtfTool
      * `/RsaCtfTool.py --publickey ../path-to-truth/key --private --output ../path-to-truth/key.private`
        * Key is in factordb
  * keyhole
    * `openssl pkeyutl -decrypt -in keyhole -out foo.dec -inkey solved_files/key.private`
    * gives us a binary file of length of 32 bytes / 256 bits
  * Lock - openssl encrypted with salted password
    * Commit message gives the cipher
    * `openssl aes-256-cbc -d -pbkdf2 -in lock -out solved_files/lock.dec -kfile solved_files/keyhole.plain`
    * Gives us a nice readme for the introduction to the puzzle
  * door - 7zip archive with password
    * `7z x -pDisobey25-6cd9-4fbf-1337-36fd9db7a835 door`
    * crackme - ELF 64-bit LSB executable, x86-64
      * Something to reverse!
    * stegano.png - a png image
      * Binwalk finds a 7zip archive at the end of the png
4. crackme
  * Multithreaded application that is pretty nasty and has several anti-debugging and anti-analysis features
  * Listens to udp 127.0.0.1:21863
  * Load it into ghidra for fun times
    * auto-analyze and then run the `ResolveX86orX64LinuxSyscallsScript.java`
      * This resolves all the linux static calls and makes our life easier
    * Start identifying standard functions from strings
      * 0x00428550 is  `__libc_start_main`
      * 0x004372b0 is `malloc`
      * 0x00438f70 is `memcopy`, or more like a function that gets the optimal memcopy pointer
      * 0x0043e180 is `memset`
      * 0x00434e70 is `free`
      * 0x00428ad0 is `glib_assert_failed` or something like that
      * 0x004300a0 is `pthread_create`
        * it is called from three places, creating threads:
          * 0x004018b5 `thread1`
          * 0x0040b6f6 `thread2`
          * 0x00422bc5 `thread3`
          * They are all Interesting
      * 0x00401880 is `init1` and not so interesting
      * 0x0040ed28 is `init` and interesting
      * 0x0040ef56 is `main` and interesting
  * Several of the functions contain `CMP; JZ;` chains that make havoc on the decompiler
    * The conditional jumps are all to illegal addresses
    * Patch the first instruction to be a unconditional jump to the end of the block
      * This will improve the decompilation
      * Also clear the now-unused code blocks and create an array there to collapse the bytes
  * The execution flow:
    1. init
      * Initialize a global state struct with function pointers and a buffer
        * One of the functions is the result of a memory search
      * Spawn
        * thread1
          1. Anti debug check
          2. sets a flag on the global struct once the check passes
        * thread2
          1. Sleep(1)
          2. Set globals.function5 to garbage
    2. main
      * Call globals.function1
      * Call globals.function0
        1. Listen for UDP data
        2. Spawn thread3 if data received
          * This is actually a loop, due to stack shenagicans
          * Change the flow of the `ret` to `BRANCH`
          * Add the destinations to ret as `COMPUTED JUMP` references
          * Run switch override script
          * See the xor loop
            * it prints "OK" if comparison matches
            * decrypt the data in cyberchef
              * Get `yassin:BlueOcean11_c0mes_up_w1th_the_b3st_Kimchi`
              * The credentials work on `kouvostoforensics.com` so we could skip the `stegano.png`
5. stegano.png
  * Evil Find The Right Tool thing, dropped this after getting the creds to kouvostotelecom, solved later after having tickets...
    1. `binwalk stego.png` -> 7zip archive, encrypted
    2. `https://github.com/DimitarPetrov/stegify`
    3. `zsteg -E "b8,rgb,lsb,xy" image.bmp > image.out`
    4. `binwalk image.out`
    5. RTTY
      * https://www.dcode.fr/baudot-code
      * `kouvostoforensics.com`
6. Kouvostoforensics.com
  * Cases
    * `<!-- wp:include "/var/www/incident_data.pcapng" -->`
    * Start looking for local file inclusion vulns
  * `robots.txt`
    * `Disallow: /wp-admin/`
    * `Allow: /wp-admin/admin-ajax.php`
  * wp-admin
    * typo in redirect, add to hosts file with the same ip
      * `94.237.12.91 kouvostoforencis.com`
  * Wordpress, so lets try to figure out the env
    * https://kouvostoforensics.com/wp-content/plugins/
    * https://wpscan.com/vulnerability/0e8930cb-e176-4406-a43f-a6032471debf/
      * Published 2024-08-09 so pretty recent vuln
    * Get the pcap
      1. `curl --insecure -u yassin:BlueOcean11_c0mes_up_w1th_the_b3st_Kimchi -X POST https://kouvostoforencis.com/wp-admin/admin-ajax.php -d "from_set_ajax=1&action=w2dc_controller_request&template=../../../../../var/www/incident_data.pcapng" -o exfil.json`
      2. Extract the base64 payload from the json response
7. incident_data.pcapng
  * memes
  * `svchost.exe`
  * `DHnc`
  * Weird traffic to and from:
    * divanodivino.xyz/dot.gif
      * Meme
    * divanodivino.xyz/submit.php
      * Meme: "Is this hacker ticket?; CS C2; You"
  * DNS
    * qrnbqqofrf.divanodivino.xyz
      * Ransomware leak site, has confidential.7z for kouvosto makkara
        * Password protected
    * pineapple.belongs.to.pizza.divanodivino.xyz
        * Meme
8. svchost.exe
  * Checks params and a key
    * We do not have the key to pass the check, did not reverse it.
  * Creates a registery key
  * XOR decrypts diavola.exe with key `"420"`
    * Extract the file and decrypt with cyberchef
    * Windows PE executable
9. diavola.exe
  * has memory segments labeled SEX0 and SEX1
  * Flow
    1. decrypts SEX1 into SEX0
    2. jumps into SEX0
    3. obfuscates library loads
      * Figure them out via dynamic analysis
      * Create a memory region for them
      * Add the functions to the artificial region
        * Alternatively a more proper way would be to create external references for them, but didn't think of it
        * Also `ImportSymbolsScript.py` in ghidra can load the symbols from a file
    4. Checks if `pineapple.belongs.to.pizza.divanodivino.xyz` resolves
      * If it does, exits
    5. Creates a key and iv
      * srand(time32()), save the seed
      * key is 32 bytes of rand
      * iv is 16 bytes of rand
    6. Hashes the key with SHA-256
    7. Derives a AES 256 key
    8. Encrypts files with AES
    9. Mangles the seed into lower case characters
    10. resolves the `<mangled seed>.divanodivino.xyz`
      * This exfiltrates the key
  * Reverse the domain from the pcap
    * `qrnbqqofrf` -> `1725110373`
    * Timestamp matches the timeline in pcap and is only 11 units off from the diavola.exe invocation
  * use the compiler explorer https://godbolt.org/ to run a snipplet on windows and create the key and iv
    * IV: `550045d6764f86cba8bf63eb6575c098`
    * Key: `47e1f729be42db4e11da9e589084ee2a6be62700991685fb9d722a9d933409a5`
    * have a decryptor ready in cyberchef for the files...
      * https://gchq.github.io/CyberChef/#recipe=AES_Decrypt(%7B'option':'Hex','string':'47e1f729be42db4e11da9e589084ee2a6be62700991685fb9d722a9d933409a5'%7D,%7B'option':'Hex','string':'550045d6764f86cba8bf63eb6575c098'%7D,'CBC','Raw','Raw',%7B'option':'Hex','string':''%7D,%7B'option':'Hex','string':''%7D)
10. DHnc
  * Encrypted somehow
  * Size about the same as cobalt strike beacon stage 2
  * After solving the puzzle virustotal also confirms it as cobalt strike
11. Weird traffic to divanodivino.xyz/dot.gif and divanodivino.xyz/submit.php
  * Binary cookie, encrypted payloads
  * Cobalt strike beacon commands
  * There are known keys for the cracked versions, lets hope they didn't change them...
    * https://github.com/DidierStevens/DidierStevensSuite
      1. `python cs-decrypt-metadata.py iG36xdqmsvZYrNKtj/uu9HemTtxPIuoFRNPYiOgdPDERcX6UCIokAUFNka3JtV8xOF5ZksJ5PkFV55a2Hsa3YerVjygjy9RdcjybsbPX7HtJkQ2/Ot8W+G270PcC2i9BEkvQzqFDM00C1HeXdP6RHltJjUHtFYtAYIM5GnbQXY0=`
      2. `python cs-parse-traffic.py -r a04a96434271b4c3f7e13251e6b38286 ../2dev_incident_data_4ops.pcapng > foo.txt`
    * The traffic gets us:
      * svchost.exe invocation to bypass reversing it (too late)
        * PizzaBox.exe --bake --key KouvostonMakkara
      * diavola.exe invocation (too late)
      * the confidential.7z password
        * `7z a a.7z -pKouvostonMakkaraGotPwnedLolXD "C:\Users\armand\backup"`
12. confidential.7z
  * decrypt the .diavola files
  * memes and a mailbox
  * get a broken `sshd` binary and ip & port where it is running
    * `94.237.112.76` port `42069`
13. sshd pwn
  * the exe has debug symbols
  * PIE is disabled
  * there is a obvious buffer overflow
  * we have two interesting functions, `disobey` and `nothingtoseehere`
    * `disobey` just does stack manipulation
    * `nothingtoseehere` reads a file, checks a value on stack and then prints the file
      * this seems to be the target
      * lets first see if we can call it in a way that it produces the file
  * time to learn pwntools
  * ROP chain
    * disobey -> 0xdeadfood filler bytes -> nothingtoseehere
    * get it to work locally
    * try remotely
    * get the store url
      * Buy ticket
      * PDF has a typo on the date
      * Report it
      * Later solvers don't have a special edition `14.-15. May` tickets
14. See you at disobey 2025 ctf
