#include "stdafx.h"
#include "windows.h"

#include "aplib.h"
#pragma comment (lib, "aplib.lib")

//#pragma warning(disable:4996)




/* 디코딩 및 임포트 테이블 복구 루틴. */
/* 디코딩 루틴은 aPLib(src/32bit/depack.asm)에서 제공되는 것을 수정하였고, 임포트 테이블 복구 루틴은 fsg 및 kkrunchy 등에서 사용되는 임포트 테이블 복구 루틴을 수정하였다. */
// https://0x00sec.org/t/pe-file-infection/401 : 어셈블리 루틴을 다루는 방식은 이 페이지를 참고하였다.
/**************************************************************/
// 0xAAAAAAAA 같은 주소들은 추후에 수정되며, .packedc 섹션에 써진다.
// 이후 이 루틴은 패킹된 바이너리의 EP가 된다.

#define db(x) __asm _emit x

__declspec(naked) int ShellcodeStart(VOID) {
	__asm {
		nop						// 32비트의 주소를 맞추기 위하여 nop 즉 0x90 명령어를 사용한다.
		nop
		nop
		push   0xAAAAAAAA		// Source. 패킹된 바이너리의 시작 위치이다.
		nop
		nop
		nop
		push   0xBBBBBBBB		// Destination. 언패킹된 바이너리가 써질 실제 위치이다.
		nop
		nop
		nop
		push   0xCCCCCCCC		// OEP. 언패킹된 프로그램의 시작 위치 (마지막 ret 명령에 의해 사용된다).

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
			jz     donedepacking			// 디패킹이 끝나면 임포트 테이블 복구 루틴으로 분기한다.
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

			donedepacking :					// 임포트 테이블 복구 루틴 시작
		MOV ESI, 0xDDDDDDDD			// 이 임포트 테이블 복구 루틴을 위해 IAT에 저장된 DLL의 이름 및 함수들의 이름을 미리 특별한 형태로 생성하고 추가하였다.
			nop							// 이 주소는 앞에서 생성되고 추가된 그 내용의 시작 주소이다.
			nop
			nop
			MOV EBX, 0xEEEEEEEE			// 현재 패킹된 바이너리의 IAT 주소. 참고로 현재 바이너리는 LoadLibraryA()와 GetProcAddress()만을 가지고 있다.

			gofirst :
			INC ESI
			LODS DWORD PTR DS : [ESI]
			XCHG EAX, EDI
			PUSH ESI
			CALL DWORD PTR DS : [EBX]	// LoadLibraryA() 호출.
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
			CALL DWORD PTR DS : [EBX + 4]	// GetProcAddress() 호출.
			STOS DWORD PTR ES : [EDI]
			JMP loopss

			end :
		popad
			ret							// OEP로 복귀

	}
}


VOID ShellcodeEnd() {

}

/**************************************************************/




/* 유틸리티 구조체 및 함수들 */
/**************************************************************/

// 파일의 존재 여부 확인.
BOOL is_FileExists(LPCTSTR szPath)
{
	DWORD dwAttrib = GetFileAttributes(szPath);
	return (dwAttrib != INVALID_FILE_ATTRIBUTES) && !(dwAttrib & FILE_ATTRIBUTE_DIRECTORY);
}


// 섹션의 경계를 맞추기 위해 사용되는 함수. 즉 alignment를 맞추기 위해 사용된다.
// ref : https://github.com/codereversing/pe_infector
unsigned int align_to_boundary(unsigned int address, unsigned int boundary) {
	return (((address + boundary - 1) / boundary) * boundary);
}


// 바이트 값을 다루기 위해 사용되는 구조체.
// ref : stackoverflow
union my_int {
	DWORD val;
	unsigned __int8 bytes[sizeof(DWORD)];
};

/**************************************************************/




/* main 함수 */
/**************************************************************/

int _tmain(int argc, _TCHAR* argv[]) {

	// 다음은 기본적인 MMF(Memory Map File) 방식을 이용하여 패킹할 바이너리를 다룬다.
	HANDLE hFile, hMap;
	DWORD dwFileSize;
	LPBYTE lpFile;
	LPCTSTR arg = argv[1];
	DWORD OriginEP;

	if (!is_FileExists(arg)) {
		printf("No File! \n");
		return 0;
	}

	hFile = CreateFile(arg, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		printf("CreateFile() Failed! \n");
		return 0;
	}

	dwFileSize = GetFileSize(hFile, NULL) + 0x00006000;

	hMap = CreateFileMapping(hFile, NULL, PAGE_READWRITE, 0, dwFileSize, NULL);
	if (hMap == 0) {
		printf("CreateFileMapping() Failed! \n");
		return 0;
	}

	lpFile = (LPBYTE)MapViewOfFile(hMap, FILE_MAP_ALL_ACCESS, 0, 0, 0);
	if (lpFile == 0) {
		printf(" MapViewOfFile() Failed! \n");
		return 0;
	}


	// 다음은 ImageHlp 구조체를 이용하여 각 헤더의 주소를 가져온다.
	/*
	섹션 헤더의 주소를 다루는 방식은 미리 설명할 필요가 있다.
	우리는 첫 번째는 .text(pifh) 그리고 두 번째는 .rdata(pish) 마지막으로 세 번째는 .data(pith)로 인식하기로 하며 이것만 고려 대상에 넣는다.
	이후 섹션들 즉 pieh 이후부터는 삭제하기로 한다.
	*/
	PIMAGE_DOS_HEADER pidh = (PIMAGE_DOS_HEADER)lpFile;
	PIMAGE_NT_HEADERS pinh = (PIMAGE_NT_HEADERS)((DWORD)pidh + pidh->e_lfanew);
	PIMAGE_OPTIONAL_HEADER pioh = (PIMAGE_OPTIONAL_HEADER)&pinh->OptionalHeader;
	PIMAGE_SECTION_HEADER pifh = (PIMAGE_SECTION_HEADER)IMAGE_FIRST_SECTION(pinh);
	PIMAGE_SECTION_HEADER pish = (PIMAGE_SECTION_HEADER)(pifh + 1);
	PIMAGE_SECTION_HEADER pith = (PIMAGE_SECTION_HEADER)(pifh + 2);
	PIMAGE_SECTION_HEADER pieh = (PIMAGE_SECTION_HEADER)(pifh + 3);


	// 뒤에서 섹션 및 파일의 경계를 다루기 위해서 사용되는 함수인 align_to_boundary() 호출을 위해 미리 변수로 저장해 놓는다.
	DWORD SectionAlign = pioh->SectionAlignment;
	DWORD FileAlign = pioh->FileAlignment;




	/* a. OEP 저장 및 임포트 테이블 복구 루틴에서 사용할 구조 생성 */

	OriginEP = pioh->AddressOfEntryPoint;


	PIMAGE_DATA_DIRECTORY oldpidd = (PIMAGE_DATA_DIRECTORY)&pioh->DataDirectory;
	PIMAGE_IMPORT_DESCRIPTOR iid = (PIMAGE_IMPORT_DESCRIPTOR)oldpidd[1].VirtualAddress;
	// IMAGE_DATA_DIRECTORY[1] => IMPORT Table
	// 즉 Data Directory의 두 번째 항의 VirtualAddress 필드를 통해 첫 IID의 주소를 구한다.
	iid = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)iid + lpFile);
	iid = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)iid - pish->VirtualAddress + pish->PointerToRawData);
	// 참고로 ImageHlp 구조체를 통해 얻은 값들은 메모리에 로드되었을 때의 주소를 나타내는데, 현재 우리는 파일 자체를 메모리로 올렸기 때문에 파일로서 위치하는 주소를 구해야 한다.
	// VirtualAddress를 빼고 동시에 PointerToRawData를 더해주는게 그것 때문이다.
	// 이후부터 iid는 메모리에 올라온 파일에 위치하는 제대로 된 값을 가리키게 된다.


	// 여기서는 처음 DLL부터 시작한다. 이후 for 문에서 다음 DLL에 대하여 계속 수행할 것이다.
	char * ims;
	// ims는 해당 DLL의 IAT 주소이며 iats 변수로 변환된다.
	PIMAGE_THUNK_DATA32 iats;
	// iats는 해당 DLL의 IAT 주소이다.
	char * nms;
	// nms는 해당 DLL의 이름의 주소이다.
	DWORD foriats;
	// foriats는 해당 DLL의 로드 이후 IAT 주소이다. 즉 임포트 테이블 복구 루틴은 이 주소에 IAT를 복구할 것이다.
	// 참고로 iats 및 nms는 우리가 참조할 값이 들어있는 주소이며(그래서 파일 오프셋 값을 갖는다), foriats는 실제 메모리 로드 후에 사용될 값이다(그래서 간단히 ImgBase 값만 더한다).
	
	union my_int mi;

	char * foruse;
	DWORD addr;

	DWORD sizz = (DWORD)pish->SizeOfRawData;
	char * buff = (char*)malloc(sizz);
	char * finalBuf = (char*)malloc(sizz);
	SecureZeroMemory(finalBuf, sizz);
	// buff는 임시 결과물을 위한 용도이며, finalBuf는 최종 결과물이 들어갈 버퍼이다.

	char null1[] = { '\01', '\0' };
	char null2[] = { '\02', '\0' };
	char null3[] = { '\03', '\0' };
	// 문서에 설명되어 있듯이 특별한 데이터를 위한 용도로서 사용된다.
	// 실제 데이터는 0x00을 가지고 있지만 우리가 만든 버퍼(char * 문자열)에서는 0x00을 끝으로 생각하기 때문에 0x00을 다른 값으로 대체하고 마지막에 다시 0x00으로 복구할 필요가 있다.


	for (;;) {
		// 각 DLL마다 이 루틴이 반복된다.

		if (iid->FirstThunk == 0x00000000)
			break;

		ims = (char *)(iid->FirstThunk + lpFile - pish->VirtualAddress + pish->PointerToRawData);
		iats = (PIMAGE_THUNK_DATA32)ims;
		nms = (char *)(iid->Name + lpFile - pish->VirtualAddress + pish->PointerToRawData);

		foriats = (DWORD)((DWORD)iid->FirstThunk + (DWORD)pioh->ImageBase);
		mi.val = (DWORD)foriats;

		for (int idx = 0; idx < sizeof(DWORD); idx++) {
			if (mi.bytes[idx] == '\00')
				mi.bytes[idx] = null2[0];
		}
		sprintf(buff, "%c", mi.bytes[0]);
		sprintf(buff + 0x1, "%c", mi.bytes[1]);
		sprintf(buff + 0x2, "%c", mi.bytes[2]);
		sprintf(buff + 0x3, "%c", mi.bytes[3]);
		// 이런 방식을 사용하는 이유는 0x00의 값이 있을 수 있으므로 이 값을 미리 0x02로 바꾸기 위해서이다.
		// 물론 뒤에서 다시 0x00으로 수정할 것이다.

		strcat(finalBuf, null1);
		// 가장 먼저 0x01을 넣는다. 이것은 각 DLL의 시작 시 마다 추가되는 것이다. 즉 0x01 다음에는 새 DLL의 IAT 주소가 나온다.
		strcat(finalBuf, buff);
		// 그리고 IAT를 복구할 주소, 즉 메모리 로드 이후의 실제 IAT 주소를 넣는다.
		sprintf(buff, "%s", nms);
		strcat(finalBuf, buff);
		strcat(finalBuf, null3);
		// 마지막으로 해당 DLL의 이름을 넣는다.


		for (;;) {
			// 이 루틴은 해당 DLL이 포함하는 각 함수들의 이름을 넣는 부분이다.
			memcpy(&foruse, iats, sizeof(iats));
			addr = (DWORD)foruse;
			if (addr == 0x00000000)
				break;

			addr = addr + (DWORD)lpFile - pish->VirtualAddress + pish->PointerToRawData + 0x2;
			sprintf(buff, "%s", addr);
			strcat(finalBuf, buff);
			strcat(finalBuf, null3);
			iats = (iats + 1);
			// 각 함수의 이름인 문자열을 버퍼에 넣는다. DLL 내의 각 함수명은 0x03으로 구분한다.
		}
		iid = (iid + 1);
	}

	int bufLen = strlen(finalBuf);
	DWORD startImport = pioh->ImageBase + pish->VirtualAddress + pish->SizeOfRawData - bufLen - 0x20;
	// 만들어진 데이터가 들어갈 위치로서, 2번째 즉 .rdata 섹션의 마지막 부분의 위치로 구한다.


	for (int m = 0; m<bufLen; m++) {
		if (*(finalBuf + m) == 0x02) {
			*(finalBuf + m) = 0x00;		// 아까 복구할 IAT 주소를 넣는 부분에서 0x00을 0x02로 바꾸었으니 다시 복구시켜준다.
		}
		if (*(finalBuf + m) == 0x03) {		// 이것은 0x03인 부분인데 크게 3가지로 나눌 수 있다.
			if (*(finalBuf + m + 1) == 0x00) {		// 이 경우는 0x03, 0x00인데, 이 데이터의 마지막 부분이므로 0x00, 0x02로 수정하여 준다.
				*(finalBuf + m) = 0x00;
				*(finalBuf + m + 1) = 0x02;
			}
			else if (*(finalBuf + m + 1) != 0x01) {	// 이 경우는 각각의 API 사이에 존재하는 0x00을 0x03으로 바꾼 경우인데,
				*(finalBuf + m) = 0x00;				// 이것을 다시 0x00으로 바꿈과 동시에 다음 문자 즉 함수의 첫 문자에 0x02를 더한다.
				*(finalBuf + m + 1) = *(finalBuf + m + 1) + 0x02;
			}
			else {						// 이 경우는 단지 원래 값이 0x00이었던 경우이므로 다시 0x00으로 바꾸어준다.
				*(finalBuf + m) = 0x00;
			}
		}
	}




	/* b. 메모리에 정리해서 올리기 */
	// 앞에서도 언급하였듯이 섹션 3개(.text와 .rdata 그리고 .data)만 고려하고 나머지 부분은 버리기로 한다.
	// 이 3 섹션을 파일처럼이 아니라 메모리에 올라온 것처럼 만들어 주기 위해서 PointerToRawData의 위치에서 VirtualAddress 위치로 이동시킨다.

	CopyMemory(lpFile + pith->VirtualAddress, lpFile + pith->PointerToRawData, pith->SizeOfRawData);	// .data(3번째) 섹션 이동
	CopyMemory(lpFile + pish->VirtualAddress, lpFile + pish->PointerToRawData, pish->SizeOfRawData);	// .rdata(2번째) 섹션 이동
	CopyMemory(lpFile + pifh->VirtualAddress, lpFile + pifh->PointerToRawData, pifh->SizeOfRawData);	// .text(1번째) 섹션 이동
	CopyMemory((void *)(startImport + lpFile - pioh->ImageBase), finalBuf, bufLen + 4);		// 위에서 IAT 복구를 위해 만들었던 내용을 .rdata 섹션의 마지막 부분으로 옮긴다.
	SecureZeroMemory((void *)(lpFile + pioh->SizeOfHeaders), (int)(pifh->PointerToRawData - pioh->SizeOfHeaders));




	/* c. 섹션 압축하기 */
	DWORD start = (DWORD)lpFile + pifh->VirtualAddress;
	DWORD dwSize = pioh->SizeOfImage;		// 바이너리 전체의 크기

	char *workmem = (char *)malloc(aP_workmem_size(dwSize));		// 작업 공간 할당
	char *compressed = (char *)malloc(aP_max_packed_size(dwSize));		// 압축된 내용이 들어갈 위치 할당

	size_t outlength = aP_pack((void *)start, compressed, dwSize, workmem, NULL, NULL);




	/* d. 섹션 3개 원하는 형태로 수정하고 나머지 섹션 헤더 지우기 */
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


	// 나머지 섹션 헤더들 지우고 3개로 설정.
	WORD erasedStart = (WORD)pieh;					// 네 번째 섹션의 위치를 구한다.
	DWORD erasedSectionStart = (DWORD)erasedStart;
	DWORD erasedSectionLast = (DWORD)pioh->SizeOfHeaders;
	SecureZeroMemory((void *)pieh, (int)(erasedSectionLast - erasedSectionStart));
	pinh->FileHeader.NumberOfSections = 3;




	/* e. 압축한 내용을 .packedc 섹션에 쓰기 */

	DWORD packedSection = (DWORD)lpFile + pish->PointerToRawData;
	memcpy((void *)packedSection, compressed, outlength);




	/* f. 데이터 디렉터리 처리하기 */
	// 데이터 디렉터리의 Import table 부분의 Size와 VirtualAddress를 새로 설정한다.

	PIMAGE_DATA_DIRECTORY pidd = (PIMAGE_DATA_DIRECTORY)&pioh->DataDirectory;

	for (int i = 0; i < 16; i++) {
		pidd[i].Size = 0x00000000;
		pidd[i].VirtualAddress = 0x00000000;;
	}

	pidd[1].Size = 0x00000074;
	pidd[1].VirtualAddress = pith->VirtualAddress;




	/* g. 디코딩 루틴 주소 수정 및 .packedc 섹션에 삽입하기 */

	DWORD decPosition = pish->PointerToRawData + outlength;

	HANDLE hHeap = HeapCreate(0, 0, dwShellcodeSize);
	LPVOID lpHeap = HeapAlloc(hHeap, HEAP_ZERO_MEMORY, dwShellcodeSize);
	memcpy(lpHeap, ShellcodeStart, dwShellcodeSize);

	OriginEP += pioh->ImageBase;
	DWORD Origin = pish->VirtualAddress + pioh->ImageBase;
	DWORD Destin = pifh->VirtualAddress + pioh->ImageBase;

	// 다음의 루프문들은 DWORD 만큼의 값을 읽어와서 비교하므로 디코딩 루틴에서 nop을 이용하여 자리를 맞추었었다.
	DWORD dwIncrementor = 0;
	for (; dwIncrementor < dwShellcodeSize; dwIncrementor++) {
		if (*((LPDWORD)lpHeap + dwIncrementor) == 0xAAAAAAAA) {
			*((LPDWORD)lpHeap + dwIncrementor) = Origin;
			break;
		}
	}

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
			*((LPDWORD)lpHeap + dwIncrementor) = startImport;
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

	memcpy((LPBYTE)(lpFile + decPosition + 0x40), lpHeap, dwShellcodeSize);
	HeapFree(hHeap, 0, lpHeap);
	HeapDestroy(hHeap);




	/* h. 기타 섹션 헤더 처리하기 */

	pioh->AddressOfEntryPoint = pish->VirtualAddress + outlength + 0x40;		// EP를 새로 만든 디코딩 루틴의 시작 위치로 설정
	pioh->SizeOfImage = pith->VirtualAddress + SectionAlign;
	pioh->SizeOfCode = pish->Misc.VirtualSize;
	pioh->SizeOfInitializedData = pith->Misc.VirtualSize;




	/* i. .importt 섹션 생성하기 */
	// 여기서는 패킹된 바이너리의 임포트 섹션을 직접 새로 만들어준다.

	SecureZeroMemory((void *)(lpFile + pith->PointerToRawData), (int)(pith->SizeOfRawData));
	// .importt 섹션을 위해 세 번째 섹션을 0x00으로 채운다.

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




	/* j. 파일 크기 줄이기 */

	UnmapViewOfFile(lpFile);
	CloseHandle(hMap);

	SetFilePointer(hFile, length, NULL, FILE_BEGIN);
	SetEndOfFile(hFile);

	CloseHandle(hFile);

	printf("end! \n");

	return 0;
}
