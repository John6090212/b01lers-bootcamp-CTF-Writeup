# b01lers bootcamp CTF Writeup
## 心得
第三次的線上賽，一樣以刷web跟crypto為主，水題超多，算是讓我更熟悉web的技巧
不過web的中階題目還是不太知道怎麼下手，感覺trace code要再加強，lua完全看不懂QQ
## Web
### Find That Data!
#### 題目:
Complete what Clu could not... Find the data in memory. https://www.youtube.com/watch?v=PQwKV7lCzEI

http://chal.ctf.b01lers.com:3001
#### 解答:
寫writeup的時候網頁已經關了XD
總之用source code給的帳號跟密碼登進去大概長這樣
就是一個不斷變動的迷宮，然後你的路一開始就被封死了
![](https://i.imgur.com/zTPCH0U.png)
印象中我是找source code中判斷到達的這個function
直接把x跟y改成你現在的位置
```javascript=
function check_data() {
  if (x === 1 && y === maxRows) {
    $.post("/mem", { token: $("#token").html() }).done(function(data) {
      alert("Memory: " + data);
    });
  }
}
```
然後flag就會噴在alert上面了
![](https://i.imgur.com/P0ZgBb9.jpg)


### Reindeer Flotilla
#### 題目:
It's time to enter the Grid. Figure out a way to pop an alert() to get your flag.

http://chal.ctf.b01lers.com:3006

Author: @MDirt
#### 解答:
網頁有一個框框可以輸入指令
![](https://i.imgur.com/5cjRSbr.png)
看到目標是要觸發alert()馬上想到XSS
自己試了一下不會只好偷看cheat sheetXD
發現這個img tag蠻好用的，可以在圖片沒出來的時候注入script
```html
<img src=# onerror=alert(1)>
```
注入成功console就會印出flag
![](https://i.imgur.com/tmOgkUk.jpg)


### First Day Inspection
#### 題目:
It's your first day working at ENCOM, but they're asking you to figure things out yourself. What an onboarding process... take a look around and see what you can find.

http://chal.ctf.b01lers.com:3005

Author: @MDirt
#### 解答:
在source code跟google chrome console還有local storage可以找到共五個flag片段
拼起來就是flag
1:flag{
2:w3lc
3:0m3_
4:t0_E
5:NC0M}
>flag{w3lc0m3_t0_ENC0M}

### Where's Tron?
#### 題目:
We've lost Tron on the grid, find him using this uplink!

http://chal.ctf.b01lers.com:3004
#### 解答:
有個可以下sql injection的console，印象中限制只有會concat "limit 20"的樣子
所以其實蠻簡單的，比較像sql練習XD
用下面三個sql就可以循序找到flag
```sql
SELECT * FROM information_schema.tables WHERE table_schema='grid'
SELECT * FROM information_schema.columns WHERE table_name='programs'
SELECT * FROM programs WHERE name LIKE 'Tron%'
```
flag:
>flag{REDACTED}

## Crypto
### Dream Stealing
#### 題目:
I've managed to steal some secrets from their subconscious, can you figure out anything from this?

附檔:
ciphertext.txt
```
Modulus: 98570307780590287344989641660271563150943084591122129236101184963953890610515286342182643236514124325672053304374355281945455993001454145469449640602102808287018619896494144221889411960418829067000944408910977857246549239617540588105788633268030690222998939690024329717050066864773464183557939988832150357227
One factor of N:  9695477612097814143634685975895486365012211256067236988184151482923787800058653259439240377630508988251817608592320391742708529901158658812320088090921919
Public key: 65537
Ciphertext: 75665489286663825011389014693118717144564492910496517817351278852753259053052732535663285501814281678158913989615919776491777945945627147232073116295758400365665526264438202825171012874266519752207522580833300789271016065464767771248100896706714555420620455039240658817899104768781122292162714745754316687483
```
#### 解答:
一看就是我會的crypto水題好朋友RSA
n跟p都給了
所以只要算出q，然後算phi=(p-1)*(q-1)，最後用ed ≡ 1 (mod n)算出e，也就是modular multiplicative inverse of ‘e’ under modulo ‘n’
下面是我用的腳本
```python
import gmpy2
from Crypto.Util.number import inverse,long_to_bytes
n = 98570307780590287344989641660271563150943084591122129236101184963953890610515286342182643236514124325672053304374355281945455993001454145469449640602102808287018619896494144221889411960418829067000944408910977857246549239617540588105788633268030690222998939690024329717050066864773464183557939988832150357227
p = 9695477612097814143634685975895486365012211256067236988184151482923787800058653259439240377630508988251817608592320391742708529901158658812320088090921919
ciphertext = 75665489286663825011389014693118717144564492910496517817351278852753259053052732535663285501814281678158913989615919776491777945945627147232073116295758400365665526264438202825171012874266519752207522580833300789271016065464767771248100896706714555420620455039240658817899104768781122292162714745754316687483
q = gmpy2.div(n,p)
phi = (p-1)*(q-1)
e = 65537
d = inverse(e,phi)
plaintext = pow(ciphertext,d,n)
print(long_to_bytes(plaintext).decode('utf-8'))
```
flag如下:
>flag{4cce551ng_th3_subc0nsc10us}

### Clear the Mind
#### 題目:
They've gotten into your mind, but haven't managed to dive that deep yet. Root them out before it becomes an issue.

附檔:
clearthemind.txt
```
n = 102346477809188164149666237875831487276093753138581452189150581288274762371458335130208782251999067431416740623801548745068435494069196452555130488551392351521104832433338347876647247145940791496418976816678614449219476252610877509106424219285651012126290668046420434492850711642394317803367090778362049205437

c = 4458558515804625757984145622008292910146092770232527464448604606202639682157127059968851563875246010604577447368616002300477986613082254856311395681221546841526780960776842385163089662821

e = 3

```
#### 解答:
一看怎麼又是我會的crypto水題好朋友RSA XD
這題因為e太小，c又遠小於n，可以直接爆root
使用python的gmpy2.iroot就可以爆root
腳本如下:
```python
import gmpy2
from Crypto.Util.number import long_to_bytes
c = 4458558515804625757984145622008292910146092770232527464448604606202639682157127059968851563875246010604577447368616002300477986613082254856311395681221546841526780960776842385163089662821
e = 3
pt,b = gmpy2.iroot(c,e)
print(long_to_bytes(pt).decode('utf-8'))
```
flag如下:
>flag{w3_need_7o_g0_d3ep3r}

### Shared Dreaming
#### 題目:
It's not just about depth you know, you need the simplest version of the idea in order for it to grow naturally in a subject's mind; it's a very subtle art.

附檔:
shareddreaming.txt
```
Hint 1: a1 ⊕ a2 ⊕ a3 ⊕ a4 = 8ba4c4dfce33fd6101cf5c56997531c024a10f1dc323eb7fe3841ac389747fb90e3418f90011ef2610fa3636cd6cf0002d19faa30d39161fbd45cc58abff6a84
Hint 2: a2 ⊕ a3 ⊕ a4 = f969375145322aba697ce9b4e00aa88e81ffe5c306b1b98148f33c4581b2ac39bc95f13b27c39f2311a590b7e27cdbdb7599f615acd70c45378e44fb319b8cb6
Hint 3: a1 ⊕ a3 = 855249b385f7b1d9923f71feb3bdee1032963ab51aa7b9d89a20c08c381e77890aa8849702d8791f8e636e833928ba6ea44c5f261983b7e29bd82e44b77fe03b
Ciphertext: flag ⊕ a3 ⊕ RandByte = f694bc3d12a0673aead8fc4fdf964f5ec0c1d938e722bf333000f300088ead0dec1e7e03720331098068c13a066ca9bca89850a8ee67feb8471af5f47b4c0f13

Where RandByte[0] == RandByte[1] and len(RandByte) == len(flag)


```
#### 解答:
首先從他的算法可以利用a ⊕ b ⊕ b = a的特性，
用Hint1 ⊕ Hint2 ⊕ Hint3 ⊕ Ciphertext得到flag ⊕ RandByte:
010b06001c560138105438531554380057090953381754150157150a3856090454171356570938130f5409381054380954540338560a5300560953135657091a

然而where那行我實在想不到有什麼用
後來突然想到flag的開頭會是flag
就把010b跟fl的hex value 666c做xor，發現結果是6767，跟where那行講的一樣
所以我大膽推測RandByte的每個byte都是67
然後把剛得到的結果跟RandByte做xor就拿到flag了
腳本如下:
```python
a = '8ba4c4dfce33fd6101cf5c56997531c024a10f1dc323eb7fe3841ac389747fb90e3418f90011ef2610fa3636cd6cf0002d19faa30d39161fbd45cc58abff6a84'
b = 'f969375145322aba697ce9b4e00aa88e81ffe5c306b1b98148f33c4581b2ac39bc95f13b27c39f2311a590b7e27cdbdb7599f615acd70c45378e44fb319b8cb6'
c = '855249b385f7b1d9923f71feb3bdee1032963ab51aa7b9d89a20c08c381e77890aa8849702d8791f8e636e833928ba6ea44c5f261983b7e29bd82e44b77fe03b'
d = 'f694bc3d12a0673aead8fc4fdf964f5ec0c1d938e722bf333000f300088ead0dec1e7e03720331098068c13a066ca9bca89850a8ee67feb8471af5f47b4c0f13'

flag_xor_randbyte = hex(int(a,16)^int(b,16)^int(c,16)^int(d,16))[2:]
flag_xor_randbyte = '0'*(128-len(flag_xor_randbyte)) + flag_xor_randbyte
print(flag_xor_randbyte)
randbyte = '67' * 64
test_result = hex(int(flag_xor_randbyte,16)^int(randbyte,16))[2:]
test_result = '0'*(128-len(test_result)) + test_result
print(bytes.fromhex(test_result).decode('utf-8'))

```
flag如下:
>flag{1f_w3_4r3_g0nn4_p3rf0rm_1nc3pt10n_th3n_w3_n33d_1m4g1n4t10n}

### Totem
#### 題目:
Is this a dream or not? Use your totem to find out. Flag format: ctf{}.
nc chal.ctf.b01lers.com 2008

附檔:
totem-template.py
```python
# You can install these packages to help w/ solving unless you have others in mind
# i.e. python3 -m pip install {name of package}
from pwn import *
import codecs
from base64 import b64decode
from string import ascii_lowercase

HOST = ''
PORT = 0

r = remote(HOST,PORT)

def bacon(s):
    # Do this

def rot13(s):
    # And this

def atbash(s):
    # And this one

def Base64(s):
    # Lastly this one

if __name__ == '__main__':
    count = 0
    while True:     
        r.recvuntil('Method: ')
        method = r.recvuntil('\n').strip()
        r.recvuntil('Ciphertext: ')
        argument = r.recvuntil('\n').strip()

        result = globals()[method.decode()](argument.decode())  # :)

        r.recv()
        r.sendline(result.encode())
        count += 1
        if count == 1000:
            print(r.recv())
            exit(0)
    

```
#### 解答:
就是那種要回答一大堆問題才會拿到flag的題目
正常會用pwntools來寫，不過他幫你寫好了XD
只剩下四種crypto相關的function叫你刻
刻完就拿到flag了
腳本如下:
```python
# You can install these packages to help w/ solving unless you have others in mind
# i.e. python3 -m pip install {name of package}
from pwn import *
import codecs
from base64 import b64decode
import string
import re
#from string import ascii_lowercase

HOST = 'chal.ctf.b01lers.com'
PORT = 2008

r = remote(HOST,PORT)
lookup = {'A':'aaaaa', 'B':'aaaab', 'C':'aaaba', 'D':'aaabb', 'E':'aabaa', 
        'F':'aabab', 'G':'aabba', 'H':'aabbb', 'I':'abaaa', 'J':'abaab', 
        'K':'ababa', 'L':'ababb', 'M':'abbaa', 'N':'abbab', 'O':'abbba', 
        'P':'abbbb', 'Q':'baaaa', 'R':'baaab', 'S':'baaba', 'T':'baabb', 
        'U':'babaa', 'V':'babab', 'W':'babba', 'X':'babbb', 'Y':'bbaaa', 'Z':'bbaab'}     
def bacon(s):
    # Do this
    s = s.lower()
    decipher = '' 
    i = 0
  
    # emulating a do-while loop 
    while True : 
        # condition to run decryption till  
        # the last set of ciphertext 
        if(i < len(s)-4): 
            # extracting a set of ciphertext 
            # from the message 
            substr = s[i:i + 5] 
            # checking for space as the first  
            # character of the substring 
            if(substr[0] != ' '): 
                ''' 
                This statement gets us the key(plaintext) using the values(ciphertext) 
                Just the reverse of what we were doing in encrypt function 
                '''
                decipher += list(lookup.keys())[list(lookup.values()).index(substr)] 
                i += 5 # to get the next set of ciphertext  
        else: 
            break # emulating a do-while loop 
  
    return decipher.lower() 

def rot13(s):
    # And this
    return codecs.encode(s, 'rot_13')

def atbash(s):
    # And this one
    N = ord('z') + ord('a')
    ans=''
    return ans.join([chr(N - ord(c)) for c in s])
    
def Base64(s):
    # Lastly this one
    return base64.b64decode(s).decode('utf-8')

if __name__ == '__main__':

    '''
    b = bacon('ABBBBABBBAABABBABAAABAABBAABAA')
    print(type(b))
    print(b)
    
    rot = rot13('uvturfg')
    print(type(rot))
    print(rot)
    b64 = Base64('aHVuY2hlZA==')
    print(type(b64))
    print(b64)
    at = atbash('irmt')
    print(type(at))
    print(at)
    '''
    
    count = 0
    while True: 
        print(count)
        r.recvuntil('Method: ')
        method = r.recvuntil('\n').strip()        
        r.recvuntil('Ciphertext: ')
        argument = r.recvuntil('\n').strip()
        #print(method.decode())
        #print(argument.decode())
        result = globals()[method.decode()](argument.decode())  # :)
        r.recv()        
        r.sendline(result.encode())
        count += 1
        if count == 1000:
            print(r.recv())
            exit(0)
```
flag如下:
>We must be dreaming, here's your flag: ctf{4n_313g4nt_s01ut10n_f0r_tr4cking_r341ity}


