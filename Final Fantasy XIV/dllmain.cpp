// dllmain.cpp : Definiuje punkt wejścia dla aplikacji DLL.
#include "pch.h"
#include <stdio.h>
#include <iostream>
#include <string>
#include <psapi.h>
#include <vector>
#include <thread>
#include <conio.h>
#include <stdio.h>

#pragma comment(lib, "dbghelp.lib")

DWORD BaseAddress = 0;
DWORD PlayerAddres = 0;
//Komórka w pamięci gdzie znajduje się adress Gracza(PlayerAddress)
DWORD PlayerAddressOffset = 0;
DWORD MonsterOffsetOnList = 0;
DWORD AttackFunctionOffset = 0;
DWORD SelectMonsterFunctionOffset = 0;
DWORD AttackFunctionECXValueOffset = 0;


//CodeCave Adresses
DWORD DeadMonsterReturnPoint = 0;


VOID Codecave(DWORD destAddress, VOID(*func)(VOID), BYTE nopCount);
VOID WriteBytesASM(DWORD destAddress, LPVOID patch, DWORD numBytes);


VOID Codecave(DWORD destAddress, VOID(*func)(VOID), BYTE nopCount)
{
	// Calculate the code cave for chat interception
	DWORD offset = (PtrToUlong(func) - destAddress) - 5;

	// Buffer of NOPs, static since we limit to 'UCHAR_MAX' NOPs
	BYTE nopPatch[0xFF] = { 0 };

	// Construct the patch to the function call
	BYTE patch[5] = { 0xE8, 0x00, 0x00, 0x00, 0x00 };
	memcpy(patch + 1, &offset, sizeof(DWORD));
	WriteBytesASM(destAddress, patch, 5);

	// We are done if we do not have NOPs
	if (nopCount == 0)
		return;

	// Fill it with nops
	memset(nopPatch, 0x90, nopCount);

	// Make the patch now
	WriteBytesASM(destAddress + 5, nopPatch, nopCount);
}
VOID WriteBytesASM(DWORD destAddress, LPVOID patch, DWORD numBytes)
{
	// Store old protection of the memory page
	DWORD oldProtect = 0;

	// Store the source address
	DWORD srcAddress = PtrToUlong(patch);

	// Make sure page is writeable
	VirtualProtect((void*)(destAddress), numBytes, PAGE_EXECUTE_READWRITE, &oldProtect);

	// Do the patch (oldschool style to avoid memcpy)
	__asm
	{
		nop						// Filler
		nop						// Filler
		nop						// Filler

		mov esi, srcAddress		// Save the address
		mov edi, destAddress	// Save the destination address
		mov ecx, numBytes		// Save the size of the patch
		Start :
		cmp ecx, 0				// Are we done yet?
			jz Exit					// If so, go to end of function

			mov al, [esi]			// Move the byte at the patch into AL
			mov[edi], al			// Move AL into the destination byte
			dec ecx					// 1 less byte to patch
			inc esi					// Next source byte
			inc edi					// Next destination byte
			jmp Start				// Repeat the process
			Exit :
		nop						// Filler
			nop						// Filler
			nop						// Filler
	}

	// Restore old page protection
	VirtualProtect((void*)(destAddress), numBytes, oldProtect, &oldProtect);
}



DWORD* SelectedMonster;
DWORD DeadMonsterID;
DWORD NPCStructurePositionOffset = 0;

struct Position
{
	float x, y, z;
};

struct Player
{
	Position* PositionOfPlayer;
};


Player PlayerInfo;


/// <summary>
/// Funkcja zwraca adress NPC do którego teleportuje się gracz
/// </summary>
/// <param name="MonsterIndex"></param>
/// <returns></returns>
DWORD TeleportPlayerToMonster(int MonsterIndex)
{
	DWORD MonsterAddr = (DWORD)PlayerAddres + (MonsterOffsetOnList * MonsterIndex);

	Position* MonsterPosition = (Position*)(MonsterAddr + NPCStructurePositionOffset);
	SelectedMonster = (DWORD*)(BaseAddress + 0x17A4270);
	printf("\nMonster %x \nPosition \n\tX:%f \n\tY:%f \n\tZ:%f\n", MonsterAddr, MonsterPosition->x, MonsterPosition->y, MonsterPosition->z);

	
	printf("\nPlayer %x \nPosition \n\tX:%f \n\tY:%f \n\tZ:%f\n", PlayerAddres, PlayerInfo.PositionOfPlayer->x, PlayerInfo.PositionOfPlayer->y, PlayerInfo.PositionOfPlayer->z);
	printf("\nPlayer % x \nPosition \n\tX: % f \n\tY: % f \n\tZ: % f\n", PlayerAddres, PlayerInfo.PositionOfPlayer->x, PlayerInfo.PositionOfPlayer->y, PlayerInfo.PositionOfPlayer->z);
	PlayerInfo.PositionOfPlayer->x = MonsterPosition->x;
	PlayerInfo.PositionOfPlayer->y = MonsterPosition->y;
	PlayerInfo.PositionOfPlayer->z = MonsterPosition->z;


	return MonsterAddr;
}



void Attack(DWORD MonsterAdr)
{

	DWORD ECXAdresss = BaseAddress + AttackFunctionECXValueOffset;
	DWORD SelectFuncAdress = BaseAddress + SelectMonsterFunctionOffset;
	DWORD AttackFuncAdress = (DWORD)(BaseAddress + AttackFunctionOffset);

	__asm {
		push MonsterAdr
		MOV ECX, ECXAdresss
		call SelectFuncAdress
	}

	__asm {
		push MonsterAdr
		MOV ECX, ECXAdresss
		call AttackFuncAdress
	}
}



int index = 1;
DWORD DeadFunctionAdress = 0;

__declspec(naked) void CC_DeadMonsterAction(void)
{
	/*Patterns
	*   0131C170 - 66 89 8F BC010000  - mov [edi+000001BC],cx
		0131C177 - 89 8F B4010000  - mov [edi+000001B4],ecx
		0131C17D - 89 8F AC010000  - mov [edi+000001AC],ecx <<
		0131C183 - 88 8F 5F170000  - mov [edi+0000175F],cl
		0131C189 - 89 8E A4020000  - mov [esi+000002A4],ecx


		0132CF52   . 51             PUSH ECX
		0132CF53   . C70424 0000000>MOV DWORD PTR SS:[ESP],0
		0132CF5A   . 8BCF           MOV ECX,EDI
		0132CF5C   . 6A 00          PUSH 0
		0132CF5E   . FF7424 14      PUSH DWORD PTR SS:[ESP+14]
		0132CF62   . 52             PUSH EDX
		0132CF63   . E8 98F1FEFF    CALL ffxiv.0131C100
	*/


	DeadFunctionAdress = BaseAddress + 0x5FC100;
	__asm
	{
		pop DeadMonsterReturnPoint

		mov DeadMonsterID,edi

		PUSHAD
		PUSHFD
	}

	if (*SelectedMonster == DeadMonsterID) { //Jeżeli zabity potwór jest tym którego aktualnie atakujemy
		index++;
		printf("selected ID: %x monster dead %x\n", *SelectedMonster, DeadMonsterID);
		Attack(TeleportPlayerToMonster(index));
	}

	__asm
	{
		POPFD
		POPAD

		call DeadFunctionAdress

		push DeadMonsterReturnPoint
		ret
	}
}



void InitVariables()
{

	BaseAddress = (DWORD)GetModuleHandle(L"ffxiv.exe");
	MonsterOffsetOnList = 0x2990;
	PlayerAddressOffset = 0x17C9698;
	NPCStructurePositionOffset = 0xB0;
	SelectMonsterFunctionOffset = 0x41E430;
	AttackFunctionECXValueOffset = 0x17A4220;
	AttackFunctionOffset = 0x41E250;


	memcpy(&PlayerAddres, (void*)(BaseAddress + PlayerAddressOffset), 4);

	PlayerInfo.PositionOfPlayer =  (Position*)(PlayerAddres + NPCStructurePositionOffset);

	printf("\nPlayer %x \nPosition \n\tX:%f \n\tY:%f \n\tZ:%f\n", PlayerAddres, PlayerInfo.PositionOfPlayer->x, PlayerInfo.PositionOfPlayer->y, PlayerInfo.PositionOfPlayer->z);

	printf("Base Adress: %x\n", BaseAddress);	
	printf("Monster Offset: %x\n", MonsterOffsetOnList);
	printf("Monster Position Structure Offset: %x\n", NPCStructurePositionOffset);
	printf("Player Offset: %x\n", PlayerAddressOffset);
	printf("Player Adress: %x\n", PlayerAddres);
}


BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
	{
		
		AllocConsole();
		printf("START \n");
		freopen("CONIN$", "r", stdin);
		freopen("CONOUT$", "w", stdout);
		freopen("CONOUT$", "w", stderr);

		
		
		InitVariables();
		Codecave(BaseAddress + 0x60CF63, CC_DeadMonsterAction, 0);
		Attack(TeleportPlayerToMonster(index));
		//0x60CF5C


		//Attack(1);

	}
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}


