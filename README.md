***

**Code**

```cpp
DWORD unprotect(DWORD addr)
{
	BYTE* tAddr = (BYTE *)addr;

	do {
		tAddr += 0x10;
	} while (!(tAddr[0] == 0x55 && tAddr[1] == 0x8B && tAddr[2] == 0xEC));

	DWORD funcSz = tAddr - (BYTE*)addr;

	PVOID nFunc = VirtualAlloc(NULL, funcSz, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (nFunc == NULL)
		return addr;

	memcpy(nFunc, (void*)addr, funcSz);

	DWORD pos = (DWORD)nFunc;
	BOOL valid = false;
	do {
		if (*(BYTE*)pos == 0x72 && *(BYTE*)(pos + 0x2) == 0xA1 && (*(BYTE*)(pos + 0x7))) {
			memcpy((void*)pos, "\xEB", 1);

			DWORD cNFunc = (DWORD)nFunc;
			do {
				if (*(BYTE*)cNFunc == 0xE8)
				{
					DWORD tFunc = addr + (cNFunc - (DWORD)nFunc);
					DWORD oFunc = (tFunc + *(DWORD*)(tFunc + 1)) + 5;

					if (oFunc % 16 == 0)
					{
						DWORD realCAddr = oFunc - cNFunc - 5;
						*(DWORD*)(cNFunc + 1) = realCAddr;
					}
					cNFunc += 5;
				}
				else
					cNFunc += 1;
			} while (cNFunc - (DWORD)nFunc < funcSz);

			valid = true;
		}
		pos += 1;
	} while (pos < (DWORD)nFunc + funcSz);

	if (!valid) {
		VirtualFree(nFunc, funcSz, MEM_RELEASE);
		return addr;
	}

	return (DWORD)nFunc;
}
```


***


**Info**

This is a small retcheck bypass that I wrote for a delayed open-source project created by Variable and I.
It works by copying the function to a separate, un-hashed, portion of memory then proceeds to remove the check.
This is based off of Brandons bypass.

***

**Example code**

```cpp
#define GETFIELD_ADDRESS 0xDEADBEEF
DWORD _rlua_getfield = unprotect(GETFIELD_ADDRESS);
```
