#include "stdafx.h"
#include "windows.h"

#include "aplib.h"
#pragma comment (lib, "aplib.lib")

#pragma warning(disable:4996)



// aPLib에서 제공되는 디코딩 루틴을 수정한 것과 fsg 및 kkrunchy 등에서 사용되는 임포트 테이블 복구 루틴을 수정한 것.
// 어셈블리 루틴을 다루는 방식은 아래에서 참고했다.
// ref : https://0x00sec.org/t/pe-file-infection/401
/**************************************************************/
#define db(x) __asm _emit x

__declspec(naked) int ShellcodeStart(VOID) {
	__asm {
		nop
		nop
		nop
		push   0xAAAAAAAA		// Source (패킹된 바이너리의 시작 위치)
		nop
		nop
		nop
		push   0xBBBBBBBB		// Destination (언패킹된 바이너리가 써질 실제 위치)
		nop
		nop
		nop
		push   0xCCCCCCCC		// OEP (언패킹된 프로그램의 시작 위치 : 마지막 ret 명령에 의해 사용된다)
		pushad

		mov    esi, [esp + 40]
		mov    edi, [esp + 36]

		cld
		mov    dl, 80h
		xor    ebx, ebx

	literal:
		movsb
		mov    bl, 2
	nexttag :
		call   getbit
		jnc    literal
		xor    ecx, ecx
		call   getbit
		jnc    codepair
		xor    eax, eax
		call   getbit
		jnc    shortmatch
		mov    bl, 2
		inc    ecx
		mov    al, 10h
	getmorebits :
		call   getbit
		adc    al, al
		jnc    getmorebits
		jnz    domatch
		stosb
		jmp    nexttag
	codepair :
		call   getgamma_no_ecx
		sub    ecx, ebx
		jnz    normalcodepair
		call   getgamma
		jmp    domatch_lastpos
	shortmatch :
		lodsb
		shr    eax, 1
		jz     donedepacking
		adc    ecx, ecx
		jmp    domatch_with_2inc
	normalcodepair :
		xchg   eax, ecx
		dec    eax
		shl    eax, 8
		lodsb
		call   getgamma
		cmp    eax, 32000
		jae    domatch_with_2inc
		cmp    ah, 5
		jae    domatch_with_inc
		cmp    eax, 7fh
		ja     domatch_new_lastpos
	domatch_with_2inc :
		inc    ecx
	domatch_with_inc :
		inc    ecx
	domatch_new_lastpos :
		xchg   eax, ebp
	domatch_lastpos :
		mov    eax, ebp
		mov    bl, 1
	domatch :
		push   esi
		mov    esi, edi
		sub    esi, eax
		rep    movsb
		pop    esi
		jmp    nexttag
	getbit :
		add    dl, dl
		jnz    stillbitsleft
		mov    dl, [esi]
		inc    esi
		adc    dl, dl
	stillbitsleft :
		ret
	getgamma :
		xor    ecx, ecx
	getgamma_no_ecx :
		inc    ecx
	getgammaloop :
		call   getbit
		adc    ecx, ecx
		call   getbit
		jc     getgammaloop
		ret

	donedepacking :					// 디코딩 루틴 시작
		MOV ESI, 0xDDDDDDDD			// IAT 복구를 위해 만들었던 내용의 시작 주소
		nop
		nop
		nop
		MOV EBX, 0xEEEEEEEE			// LoadLibraryA()와 GetProcAddress() 호출을 위한 IAT 주소
	gofirst :
		INC ESI
		LODS DWORD PTR DS : [ESI]
		XCHG EAX, EDI
		PUSH ESI
		CALL DWORD PTR DS : [EBX]		// LoadLibraryA()
		XCHG EAX, EBP
	loopss :
		LODS BYTE PTR DS : [ESI]
		TEST AL, AL
		JNE loopss
		DEC BYTE PTR DS : [ESI]
		JE gofirst
		JNS gooep
		INC ESI
		LODS DWORD PTR DS : [ESI]
		PUSH EAX
		JMP getproc
		gooep :
		DEC BYTE PTR DS : [ESI]
		JE end
		PUSH ESI
	getproc :
		PUSH EBP
		CALL DWORD PTR DS : [EBX + 4]		// GetProcAddress()
		STOS DWORD PTR ES : [EDI]
		JMP loopss
	end :
		popad
		ret					// OEP로 복귀

	}
}

VOID ShellcodeEnd() {

}
/**************************************************************/



// 섹션 경게를 맞추기 위한 함수와 바이트 값을 다루기 위한 함수
/**************************************************************/

BOOL is_FileExists(LPCTSTR szPath)
{
	DWORD dwAttrib = GetFileAttributes(szPath);
	return (dwAttrib != INVALID_FILE_ATTRIBUTES) && !(dwAttrib & FILE_ATTRIBUTE_DIRECTORY);
}

unsigned int align_to_boundary(unsigned int address, unsigned int boundary) {
	return (((address + boundary - 1) / boundary) * boundary);
}	// ref : stackoverflow
	// alignment를 맞추기 위해 사용되는 함수

union my_int {
	DWORD val;
	unsigned __int8 bytes[sizeof(DWORD)];
};	// ref : stackoverflow
/**************************************************************/






// main 함수
/**************************************************************/
int _tmain(int argc, _TCHAR* argv[]) {

	HANDLE hFile, hMap;
	DWORD dwFileSize;
	LPBYTE lpFile;
	LPCTSTR arg = argv[1];
	DWORD OriginEP;

	if (!is_FileExists(arg)) {
		printf_s("No File! \n");
		return 0;
	}

	hFile = CreateFile(arg, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		printf_s("CreateFile Failed! \n");
		return 0;
	}

	dwFileSize = GetFileSize(hFile, NULL) + 0x00006000;

	hMap = CreateFileMapping(hFile, NULL, PAGE_READWRITE, 0, dwFileSize, NULL);
	if (hMap == 0) {
		printf_s("CreateFileMapping Failed! \n");
		return 0;
	}

	lpFile = (LPBYTE)MapViewOfFile(hMap, FILE_MAP_ALL_ACCESS, 0, 0, 0);
	if (lpFile == 0) {
		printf_s(" MapViewOfFile Failed! \n");
		return 0;
	}

	PIMAGE_DOS_HEADER pidh = (PIMAGE_DOS_HEADER)lpFile;
	PIMAGE_NT_HEADERS pinh = (PIMAGE_NT_HEADERS)((DWORD)pidh + pidh->e_lfanew);
	PIMAGE_OPTIONAL_HEADER pioh = (PIMAGE_OPTIONAL_HEADER)&pinh->OptionalHeader;
	PIMAGE_SECTION_HEADER pifh = (PIMAGE_SECTION_HEADER)IMAGE_FIRST_SECTION(pinh);
	PIMAGE_SECTION_HEADER pish = (PIMAGE_SECTION_HEADER)(pifh + 1);
	PIMAGE_SECTION_HEADER pith = (PIMAGE_SECTION_HEADER)(pish + 1);
	PIMAGE_SECTION_HEADER pieh = (PIMAGE_SECTION_HEADER)(pifh + 3);


	// align_to_boundary()에서 사용되는 값들 위해 저장
	DWORD SectionAlign = pioh->SectionAlignment;
	DWORD FileAlign = pioh->FileAlignment;



	// a. OEP 저장 및 임포트 테이블의 내용을 언패킹 루틴에서 사용할 수 있게 만들어줌 	
	// 관련 내용은 문서에 나와있다.

	OriginEP = pioh->AddressOfEntryPoint;

	PIMAGE_DATA_DIRECTORY savepidd = (PIMAGE_DATA_DIRECTORY)&pioh->DataDirectory;
	PIMAGE_IMPORT_DESCRIPTOR iid = (PIMAGE_IMPORT_DESCRIPTOR)savepidd[1].VirtualAddress;
	// IMAGE_DATA_DIRECTORY[1] => IMPORT Table
	
	iid = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)iid + lpFile);
	iid = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)iid - pish->VirtualAddress + pish->PointerToRawData);
	char * nms = (char *)(iid->Name + lpFile - pish->VirtualAddress + pish->PointerToRawData);
	char * ims = (char *)(iid->FirstThunk + lpFile - pish->VirtualAddress + pish->PointerToRawData);
	char * realaddr;
	PIMAGE_THUNK_DATA32 iats = (PIMAGE_THUNK_DATA32)ims;
	char * foruse;
	memcpy(&foruse, iats, sizeof(iats));
	DWORD addr = (DWORD)foruse;

	DWORD sizz = (DWORD)pish->SizeOfRawData;
	char * buff = (char*)malloc(sizz);
	char * buff2 = (char*)malloc(sizz);
	SecureZeroMemory(buff2, sizz);
	DWORD sizes;
	char nulll[] = { '\01', '\0' };
	char nulll2[] = { '\02', '\0' };
	char nulll3[] = { '\03', '\0' };
	char last[] = { '\03', '\0', '\0', '\0' };
	DWORD foriats;
	union my_int mi;
	int idx;


	for (;;) {
		ims = (char *)(iid->FirstThunk + lpFile - pish->VirtualAddress + pish->PointerToRawData);
		iats = (PIMAGE_THUNK_DATA32)ims;

		if (iid->FirstThunk == 0x00000000)
			break;

		nms = (char *)(iid->Name + lpFile - pish->VirtualAddress + pish->PointerToRawData);

		foriats = (DWORD)((DWORD)iid->FirstThunk + (DWORD)pioh->ImageBase);

		mi.val = (DWORD)foriats;

		for (idx = 0; idx < sizeof(DWORD); idx++) {
			if (mi.bytes[idx] == '\00')
				mi.bytes[idx] = nulll2[0];
		}
		sprintf(buff, "%c", mi.bytes[0]);
		sprintf(buff + 0x1, "%c", mi.bytes[1]);
		sprintf(buff + 0x2, "%c", mi.bytes[2]);
		sprintf(buff + 0x3, "%c", mi.bytes[3]);
		strcat(buff2, nulll);
		strcat(buff2, buff);

		sprintf(buff, "%s", nms);
		strcat(buff2, buff);
		strcat(buff2, nulll3);


		for (;;) {

			memcpy(&foruse, iats, sizeof(iats));
			DWORD addr = (DWORD)foruse;
			if (addr == 0x00000000)
				break;

			addr = addr + (DWORD)lpFile - pish->VirtualAddress + pish->PointerToRawData + 0x2;
			sprintf(buff, "%s", addr);
			strcat(buff2, buff);
			strcat(buff2, nulll3);
			iats = (iats + 1);
		}
		iid = (iid + 1);

	}
	int lenghth = strlen(buff2);
	DWORD startimport = pioh->ImageBase + pish->VirtualAddress + pish->SizeOfRawData - lenghth - 0x20;
	// 만들어진 결과 내용이 들어갈 위치로서, 2번째 즉 .rdata 섹션의 마지막 부분의 위치로 구한다.


	for (int m = 0; m<lenghth; m++) {
		if (*(buff2 + m) == 0x02) {
			*(buff2 + m) = 0x00;
		}
		if (*(buff2 + m) == 0x03) {
			if (*(buff2 + m + 1) == 0x00) {
				*(buff2 + m) = 0x00;
				*(buff2 + m + 1) = 0x02;
			}
			else if (*(buff2 + m + 1) != 0x01) {
				*(buff2 + m) = 0x00;
				*(buff2 + m + 1) = *(buff2 + m + 1) + 0x02;
			}
			else {
				*(buff2 + m) = 0x00;
			}
		}
	}




	// b. 메모리에 정리해서 올리기
	// 먼저 여기서는 섹션 3개(.text와 .rdata 그리고 .data)만 고려한다. 나머지 부분은 버리기로 한다.
	// 이 3 섹션을 파일처럼이 아니라 메모리에 올라온 것처럼 만들어 주기 위해서 PointerToRawData의 위치에서 VirtualAddress 위치로 이동시킨다.

	CopyMemory(lpFile + pith->VirtualAddress, lpFile + pith->PointerToRawData, pith->SizeOfRawData);	// .data(3번째) 섹션 이동
	CopyMemory(lpFile + pish->VirtualAddress, lpFile + pish->PointerToRawData, pish->SizeOfRawData);	// .rdata(2번째) 섹션 이동
	CopyMemory(lpFile + pifh->VirtualAddress, lpFile + pifh->PointerToRawData, pifh->SizeOfRawData);	// .text(1번째) 섹션 이동
	CopyMemory((void *)(startimport + lpFile - pioh->ImageBase), buff2, lenghth + 4);		// 위에서 IAT 복구를 위해 만들었던 내용을 .rdata 섹션의 마지막 부분으로 옮긴다.
	SecureZeroMemory((void *)(lpFile + pioh->SizeOfHeaders), (int)(pifh->PointerToRawData - pioh->SizeOfHeaders));




	// c. 섹션 압축하기
	DWORD start = (DWORD)lpFile + pifh->VirtualAddress;
	DWORD dwSize = pioh->SizeOfImage;		// 바이너리 전체의 크기

	char *workmem = (char *)malloc(aP_workmem_size(dwSize));		// 작업 공간 할당
	char *compressed = (char *)malloc(aP_max_packed_size(dwSize));		// 압축된 내용이 들어갈 위치 할당

	size_t outlength = aP_pack((void *)start, compressed, dwSize, workmem, NULL, NULL);




	// d. 섹션 3개 처리하고 나머지 부분 지우기
	DWORD dwShellcodeSize = (DWORD)ShellcodeEnd - (DWORD)ShellcodeStart;

	const char * sectionName = ".nothing";
	CopyMemory(pifh->Name, sectionName, 8);
	pifh->Misc.VirtualSize = dwSize;
	//pifh->VirtualAddress;
	pifh->SizeOfRawData = 0x00000000;
	//pifh->PointerToRawData;
	pifh->Characteristics = 0xE0000020;

	sectionName = ".packedc";
	CopyMemory(pish->Name, sectionName, 8);
	pish->Misc.VirtualSize = align_to_boundary(outlength + dwShellcodeSize, SectionAlign) + SectionAlign;
	pish->VirtualAddress = pifh->VirtualAddress + pifh->Misc.VirtualSize;
	pish->SizeOfRawData = align_to_boundary(outlength + dwShellcodeSize, SectionAlign) + 0x200;
	// 디버깅 루틴도 이 섹션에 들어갈 것이므로 이 크기도 고려한다.
	pish->PointerToRawData = pifh->PointerToRawData;
	pish->Characteristics = 0xE0000040;

	sectionName = ".importt";
	CopyMemory(pith->Name, sectionName, 8);
	pith->Misc.VirtualSize = 0x1000;
	pith->VirtualAddress = pish->VirtualAddress + pish->Misc.VirtualSize;
	pith->SizeOfRawData = 0x00000200;
	pith->PointerToRawData = pish->PointerToRawData + pish->SizeOfRawData;
	pith->Characteristics = 0xC0000040;


	// 나머지 섹션 부분 지우기
	WORD erasedStart = (WORD)pieh;		// 네 번째 섹션의 위치를 구한다.
	DWORD erasedSectionStart = (DWORD)erasedStart;
	DWORD erasedSectionLast = (DWORD)pioh->SizeOfHeaders;

	SecureZeroMemory((void *)pieh, (int)(erasedSectionLast - erasedSectionStart));

	pinh->FileHeader.NumberOfSections = 3;




	// e. 압축한 내용을 .packedc 섹션에 쓰기

	DWORD packedEnd = (DWORD)lpFile + pish->PointerToRawData;
	memcpy((void *)packedEnd, compressed, outlength);




	// f. 데이터 디렉터리 처리하기
	// 데이터 디렉터리의 Import table 부분의 Size와 VirtualAddress를 새로 설정한다.
	PIMAGE_DATA_DIRECTORY pidd = (PIMAGE_DATA_DIRECTORY)&pioh->DataDirectory;

	for (int i = 0; i < 16; i++) {
		pidd[i].Size = 0x00000000;
		pidd[i].VirtualAddress = 0x00000000;;
	}

	pidd[1].Size = 0x00000074;
	pidd[1].VirtualAddress = pith->VirtualAddress;




	// g. 디코딩 루틴 처리하기

	DWORD dwCount = 0;
	DWORD dwPosition = pish->PointerToRawData + outlength;

	HANDLE hHeap = HeapCreate(0, 0, dwShellcodeSize);
	LPVOID lpHeap = HeapAlloc(hHeap, HEAP_ZERO_MEMORY, dwShellcodeSize);
	memcpy(lpHeap, ShellcodeStart, dwShellcodeSize);

	OriginEP += pioh->ImageBase;
	DWORD Origin = pish->VirtualAddress + pioh->ImageBase;
	DWORD Destin = pifh->VirtualAddress + pioh->ImageBase;

	DWORD dwIncrementor = 0;
	for (; dwIncrementor < dwShellcodeSize; dwIncrementor++) {
		if (*((LPDWORD)lpHeap + dwIncrementor) == 0xAAAAAAAA) {
			*((LPDWORD)lpHeap + dwIncrementor) = Origin;
			break;
		}
	}
	// 다음에 나올 것들도 포함해서 이 3개의 루프문은 DWORD 만큼의 값을 읽어와서 비교한다. 
	// 이 부분에 주의해야 할 것이 DWORD 단위를 읽기 때문에, 위에서 보면 알겠지만 앞에다 NOP을 붙이던지 해서 단위를 맞출 수 밖에 없다.

	dwIncrementor = 0;
	for (; dwIncrementor < dwShellcodeSize; dwIncrementor++) {
		if (*((LPDWORD)lpHeap + dwIncrementor) == 0xBBBBBBBB) {
			*((LPDWORD)lpHeap + dwIncrementor) = Destin;
			break;
		}
	}

	dwIncrementor = 0;
	for (; dwIncrementor < dwShellcodeSize; dwIncrementor++) {
		if (*((LPDWORD)lpHeap + dwIncrementor) == 0xCCCCCCCC) {
			*((LPDWORD)lpHeap + dwIncrementor) = OriginEP;
			break;
		}
	}

	dwIncrementor = 0;
	for (; dwIncrementor < dwShellcodeSize; dwIncrementor++) {
		if (*((LPDWORD)lpHeap + dwIncrementor) == 0xDDDDDDDD) {
			*((LPDWORD)lpHeap + dwIncrementor) = startimport;
			break;
		}
	}

	DWORD NewIat = pioh->ImageBase + 0x28 + pith->VirtualAddress;
	dwIncrementor = 0;
	for (; dwIncrementor < dwShellcodeSize; dwIncrementor++) {
		if (*((LPDWORD)lpHeap + dwIncrementor) == 0xEEEEEEEE) {
			*((LPDWORD)lpHeap + dwIncrementor) = NewIat;
			break;
		}
	}

	memcpy((LPBYTE)(lpFile + dwPosition + 0x40), lpHeap, dwShellcodeSize);
	HeapFree(hHeap, 0, lpHeap);
	HeapDestroy(hHeap);

	SecureZeroMemory((void *)(lpFile + pith->PointerToRawData), (int)(pith->SizeOfRawData));
	// .rdata 섹션 zerocpy





	// h. 기타 섹션 헤더 처리하기

	pioh->AddressOfEntryPoint = pish->VirtualAddress + outlength + 0x40;		// EP를 새로 만든 디코딩 루틴의 시작 위치로 설정
	pioh->SizeOfImage = pith->VirtualAddress + SectionAlign;
	pioh->SizeOfCode = pish->Misc.VirtualSize;
	pioh->SizeOfInitializedData = pith->Misc.VirtualSize;




	// i. .importt 섹션 처리하기
	// 일일이 직접 만들어 준다.

	PIMAGE_IMPORT_DESCRIPTOR piid = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)lpFile + (DWORD)pith->PointerToRawData);
	PIMAGE_IMPORT_DESCRIPTOR piid2 = (PIMAGE_IMPORT_DESCRIPTOR)(piid + 1);

	piid->OriginalFirstThunk = 0x00000000;
	piid->TimeDateStamp = 0x00000000;
	piid->ForwarderChain = 0x00000000;
	piid->Name = (DWORD)pith->VirtualAddress + 0x00000038;
	piid->FirstThunk = (DWORD)pith->VirtualAddress + 0x00000028;

	piid2->OriginalFirstThunk = 0x00000000;
	piid2->TimeDateStamp = 0x00000000;
	piid2->ForwarderChain = 0x00000000;
	piid2->Name = 0x00000000;
	piid2->FirstThunk = 0x00000000;

	PIMAGE_IMPORT_BY_NAME iname = (PIMAGE_IMPORT_BY_NAME)((DWORD)lpFile + (DWORD)pith->PointerToRawData + 0x00000038);
	PIMAGE_THUNK_DATA32 thunk32_1 = (PIMAGE_THUNK_DATA32)((DWORD)lpFile + (DWORD)pith->PointerToRawData + 0x00000028);
	PIMAGE_THUNK_DATA32 thunk32_2 = (PIMAGE_THUNK_DATA32)((DWORD)lpFile + (DWORD)pith->PointerToRawData + 0x0000002C);
	PIMAGE_THUNK_DATA32 thunk32_3 = (PIMAGE_THUNK_DATA32)((DWORD)lpFile + (DWORD)pith->PointerToRawData + 0x00000030);

	char dllname[] = { 'K', 'E', 'R', 'N', 'E', 'L', '3', '2', '.', 'D', 'L', 'L', '\0', '\0' };

	char apiname1[] = { '\0', '\0', 'L', 'o', 'a', 'd', 'L', 'i', 'b', 'r', 'a', 'r', 'y', 'A' };
	DWORD apiadd1 = (DWORD)pith->VirtualAddress + 0x00000044;
	PVOID papiadd1 = &apiadd1;
	DWORD apinameadd1 = (DWORD)lpFile + (DWORD)pith->PointerToRawData + 0x00000044;

	char apiname2[] = { '\0', '\0', 'G', 'e', 't', 'P', 'r', 'o', 'c', 'A', 'd', 'd', 'r', 'e', 's', 's' };
	DWORD apiadd2 = (DWORD)pith->VirtualAddress + 0x00000052;
	PVOID papiadd2 = &apiadd2;
	DWORD apinameadd2 = (DWORD)lpFile + (DWORD)pith->PointerToRawData + 0x00000052;

	char apiname3[] = { '\0', '\0', 'V', 'i', 'r', 't', 'u', 'a', 'l', 'P', 'r', 'o', 't', 'e', 'c', 't' };
	DWORD apiadd3 = (DWORD)pith->VirtualAddress + 0x00000062;
	PVOID papiadd3 = &apiadd3;
	DWORD apinameadd3 = (DWORD)lpFile + (DWORD)pith->PointerToRawData + 0x00000062;

	memcpy((void *)iname, dllname, sizeof(dllname));

	memcpy((void *)thunk32_1, papiadd1, sizeof(apiadd1));
	memcpy((void *)thunk32_2, papiadd2, sizeof(apiadd2));
	memcpy((void *)thunk32_3, papiadd3, sizeof(apiadd3));

	memcpy((void *)apinameadd1, apiname1, sizeof(apiname1));
	memcpy((void *)apinameadd2, apiname2, sizeof(apiname2));
	memcpy((void *)apinameadd3, apiname3, sizeof(apiname3));

	SecureZeroMemory((void *)(lpFile + pith->PointerToRawData + pidd[1].Size), (int)(dwFileSize - (pith->PointerToRawData + pidd[1].Size)));

	DWORD length = (DWORD)(pith->PointerToRawData + pith->SizeOfRawData);




	// j. 파일 크기 줄이기

	UnmapViewOfFile(lpFile);
	CloseHandle(hMap);

	SetFilePointer(hFile, length, NULL, FILE_BEGIN);
	SetEndOfFile(hFile);

	CloseHandle(hFile);

	printf_s("end! \n");

	return 0;
}
